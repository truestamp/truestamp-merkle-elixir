// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// The sources, deviations and notes written here quote short upstream names,
// all Apache-2.0: test-case names from github.com/sigstore/rekor@v1.5.4
// pkg/verify/verify_test.go (LICENSE-rekor), from
// github.com/sigstore/rekor-tiles@v0.1.11 pkg/verify/verify_test.go
// (LICENSE-rekor-tiles) and from github.com/cosmos/ics23/go@v0.11.0
// vectors_data_test.go (LICENSE-ics23); bundle-verify directory names of
// github.com/sigstore/sigstore-conformance at commit
// 767b4a7316a1186f0a5b4387d877f51d2a33c59f (LICENSE-sigstore-conformance); and
// the "deadbeef" placeholder of github.com/sigstore/sigstore-go@v1.3.0
// pkg/tlog/entry_test.go (LICENSE-sigstore-go). See NOTICE.

package main

import (
	"bytes"
	"fmt"
	"strings"

	ics23 "github.com/cosmos/ics23/go"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	implementation = "production-logs (sigstore-go, rekor, tessera/serverless-log, ics23)"
	version        = "sigstore-go v1.3.0; rekor v1.5.4; tessera v1.0.4; serverless-log v0.0.0-20260922103222-068d1cc47e5e; ics23/go v0.11.0 (testdata at tag go/v0.11.0, commit 16ead2358595639df8ee8c31306ac0eeda2e904f); rekor-tiles v0.1.11; sigstore-conformance commit 767b4a7316a1186f0a5b4387d877f51d2a33c59f; verifier transparency-dev/merkle v0.0.2"
	license        = "Apache-2.0"
	genPrefix      = "generated: "
)

type builder struct {
	f                     *Fixture
	errs                  []string
	literalChecks         int
	published             []pubCase
	icsBatchItemsVerified int
	icsGenAccepted        int
	icsGenTotal           int
}

type pubCase struct {
	inc  Inclusion
	leaf []byte
	path [][]byte
	root []byte
	ex   *ics23.ExistenceProof
	// noGen marks a case whose proof repeats an earlier published case exactly,
	// so generate() does not derive the same corruptions from it twice.
	noGen bool
}

// caseKey identifies a proof by its content: leaf, index, size, path and root.
func caseKey(leaf []byte, m, n uint64, path [][]byte, root []byte) string {
	return fmt.Sprintf("%x|%d|%d|%x|%x", leaf, m, n, path, root)
}

// addPublishedDedup is addPublished for the sources added in round 3
// (sigstore-conformance, rekor-tiles): a case whose proof repeats an earlier
// published case exactly is still published under its own name, but generate()
// skips it.
func (b *builder) addPublishedDedup(inc Inclusion) {
	leaf, path, root := decodeCase(inc)
	key := caseKey(leaf, inc.LeafIndex, inc.TreeSize, path, root)
	dup := false
	for _, pc := range b.published {
		if caseKey(pc.leaf, pc.inc.LeafIndex, pc.inc.TreeSize, pc.path, pc.root) == key {
			dup = true
			break
		}
	}
	b.addPublished(inc, nil)
	b.published[len(b.published)-1].noGen = dup
}

func (b *builder) fail(format string, args ...any) {
	b.errs = append(b.errs, fmt.Sprintf(format, args...))
}

func (b *builder) expect(cond bool, format string, args ...any) {
	b.literalChecks++
	if !cond {
		b.fail(format, args...)
	}
}

func tdmRoot(lh [][]byte) []byte {
	if len(lh) == 0 {
		return rfc6962.DefaultHasher.EmptyRoot()
	}
	rf := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	r := rf.NewEmptyRange(0)
	for _, h := range lh {
		if err := r.Append(h, nil); err != nil {
			panic(err)
		}
	}
	root, err := r.GetRootHash(nil)
	if err != nil {
		panic(err)
	}
	return root
}

// verdicts returns transparency-dev/merkle's verdict (the fixture's "valid") and
// the RFC 9162 section 2.1.3.2 reference's.
func verdicts(leaf []byte, m, n uint64, path [][]byte, root []byte) (tdm, rfc bool) {
	tdm = proof.VerifyInclusion(rfc6962.DefaultHasher, m, n, leaf, path, root) == nil
	rfc = refVerify(leaf, m, n, path, root)
	return
}

func decodeCase(inc Inclusion) (leaf []byte, path [][]byte, root []byte) {
	leaf, root = mustHex(inc.LeafHash), mustHex(inc.Root)
	path = [][]byte{}
	for _, p := range inc.Path {
		path = append(path, mustHex(p))
	}
	return
}

// addPublished records a case built from upstream data: "valid" is what
// transparency-dev/merkle returns; any disagreement with the upstream
// assertion or with RFC 9162 becomes a discrepancy.
func (b *builder) addPublished(inc Inclusion, ex *ics23.ExistenceProof) {
	leaf, path, root := decodeCase(inc)
	tdm, rfc := verdicts(leaf, inc.LeafIndex, inc.TreeSize, path, root)
	inc.Valid = tdm
	if tdm != rfc {
		inc.RFC9162Valid = bp(rfc)
		b.f.Discrepancies = append(b.f.Discrepancies, fmt.Sprintf("%s: transparency-dev/merkle says valid=%v, RFC 9162 section 2.1.3.2 says %v", inc.Name, tdm, rfc))
	}
	if (inc.UpstreamExpectation == "valid" && !tdm) || (inc.UpstreamExpectation == "invalid" && tdm) {
		b.f.Discrepancies = append(b.f.Discrepancies, fmt.Sprintf("%s: upstream expects %s, transparency-dev/merkle says valid=%v", inc.Name, inc.UpstreamExpectation, tdm))
	}
	b.f.Inclusion = append(b.f.Inclusion, inc)
	b.published = append(b.published, pubCase{inc: inc, leaf: leaf, path: path, root: root, ex: ex})
}

// generate adds, for every published proof that verifies, the two exact-length
// corruptions no earlier fixture has at these sizes: the path cut short by one
// element with the root recomputed from what is left (so only the length is
// wrong), and the path extended by one element (the case's own leaf hash) with
// the root recomputed through it, once as a left and once as a right sibling.
// RFC 9162 section 2.1.3.2 rejects all three (sn != 0 at the end; sn == 0 with
// an element left). For ics23 cases the same corruption is also expressed as
// ics23 inner ops and run through ics23's own ExistenceProof.Verify.
func (b *builder) generate() {
	h := rfc6962.DefaultHasher
	for _, pc := range b.published {
		if !pc.inc.Valid || len(pc.path) == 0 || pc.noGen {
			continue
		}
		inc := pc.inc
		trunc := pc.path[:len(pc.path)-1]
		r, _, ok := refRun(pc.leaf, inc.LeafIndex, inc.TreeSize, trunc)
		if !ok {
			b.fail("generation: truncated chain failed for %s", inc.Name)
			continue
		}
		type variant struct {
			what string
			path [][]byte
			root []byte
			op   *ics23.InnerOp
		}
		vs := []variant{
			{"path cut to its first " + fmt.Sprint(len(trunc)) + " of " + fmt.Sprint(len(pc.path)) + " elements, root recomputed from the remaining elements (only the length is wrong)", trunc, r, nil},
			{"path extended by the leaf hash as an extra left sibling, root = node(leaf_hash, root)", append(append([][]byte{}, pc.path...), pc.leaf), h.HashChildren(pc.leaf, pc.root),
				&ics23.InnerOp{Hash: ics23.HashOp_SHA256, Prefix: append([]byte{1}, pc.leaf...)}},
			{"path extended by the leaf hash as an extra right sibling, root = node(root, leaf_hash)", append(append([][]byte{}, pc.path...), pc.leaf), h.HashChildren(pc.root, pc.leaf),
				&ics23.InnerOp{Hash: ics23.HashOp_SHA256, Prefix: []byte{1}, Suffix: pc.leaf}},
		}
		for _, v := range vs {
			tdm, rfc := verdicts(pc.leaf, inc.LeafIndex, inc.TreeSize, v.path, v.root)
			g := Inclusion{
				Name:                genPrefix + v.what + "; from " + inc.Name,
				LeafHash:            inc.LeafHash,
				LeafIndex:           inc.LeafIndex,
				TreeSize:            inc.TreeSize,
				Path:                hxs(v.path),
				Root:                hx(v.root),
				Valid:               tdm,
				UpstreamExpectation: "none",
			}
			b.expect(!rfc, "generation: RFC reference accepts %s", g.Name)
			if tdm != rfc {
				g.RFC9162Valid = bp(rfc)
				b.f.Discrepancies = append(b.f.Discrepancies, fmt.Sprintf("%s: transparency-dev/merkle says valid=%v, RFC 9162 section 2.1.3.2 says %v", g.Name, tdm, rfc))
			}
			b.f.Inclusion = append(b.f.Inclusion, g)
			if pc.ex != nil {
				ops := append([]*ics23.InnerOp{}, pc.ex.Path...)
				if v.op == nil {
					ops = ops[:len(ops)-1]
				} else {
					ops = append(ops, v.op)
				}
				alt := &ics23.ExistenceProof{Key: pc.ex.Key, Value: pc.ex.Value, Leaf: pc.ex.Leaf, Path: ops}
				b.icsGenTotal++
				if alt.Verify(ics23.TendermintSpec, v.root, pc.ex.Key, pc.ex.Value) == nil {
					b.icsGenAccepted++
				}
			}
		}
	}
}

func build() (*Fixture, *builder) {
	f := &Fixture{
		Implementation: implementation,
		Version:        version,
		License:        license,
		HashChecks:     []HashCheck{},
		Trees:          []Tree{},
		Inclusion:      []Inclusion{},
		Deviations:     []string{},
		Discrepancies:  []string{},
	}
	b := &builder{f: f}
	b.checkVendored()
	g := b.golden()
	b.rekor()
	b.sigstore()
	ics := b.ics23()
	b.rekorTiles()
	conf := b.conformance()
	b.generate()

	f.Sources = sources()
	f.Deviations = append(f.Deviations,
		fmt.Sprintf("ics23 (github.com/cosmos/ics23/go v0.11.0) ExistenceProof.Verify carries no leaf index and no tree size, so it is a hash-chain check with no RFC 9162 section 2.1.3.2 length rule: it accepts %d of the %d generated ics23-shaped length corruptions (path cut short by one with the root recomputed, or extended by one sibling on either side with the root recomputed), all of which transparency-dev/merkle and RFC 9162 reject. This is by design (ics23 proves key/value membership under a root, not a position in a sized tree), so it is recorded here and not as a discrepancy: every 'valid' in this file is transparency-dev/merkle's verdict.", b.icsGenAccepted, b.icsGenTotal),
		"ics23 leaf_index and tree_size are not part of the vector: leaf_index is derived from the inner-op sides at the generator's tree size (proofs-tendermint Makefile), and several sizes fit each file (see notes). The ics23 leaf is SHA-256(0x00 || varint(len key) || key || varint(32) || SHA-256(value)); its 54-byte leaf data is given in hash_checks.",
		"The golden log (tessera, serverless-log) and rekor's TestConsistency log are held as trees and hash checks only: neither publishes an inclusion proof (their tests compute proofs at run time).",
		"sigstore-go and rekor are thin wrappers over transparency-dev/merkle (rekor pkg/verify/verify.go:137-177), so their proofs confirm production data, not an independent verifier.",
		"sigstore-conformance asserts outcomes for whole bundles (a directory ending in _fail must fail verification), not for inclusion proofs. Each of its cases' upstream_expectation is this program's reading of the directory's README: 'valid' only where the whole bundle must verify, 'invalid' only where the README names the inclusion proof (plus the checkpoint-wrong-roothash_fail case checked against the checkpoint's own root), and 'none' otherwise. Checkpoint signatures are checked only for production Rekor v1 entries; the Rekor v2, staging and local log keys are not vendored. rekor-tiles, like rekor, is a thin wrapper over transparency-dev/merkle (pkg/verify/verify.go:30-40).",
	)
	f.Notes = notes(g, ics, conf, b)
	return f, b
}

func notes(g goldenResult, ics []ics23FileResult, conf conformanceResult, b *builder) string {
	var icsFits, icsRepeats []string
	for _, r := range ics {
		icsFits = append(icsFits, fmt.Sprintf("%s claimed %d, vector allows %s", r.file, r.size, r.feasible))
		for _, rep := range r.repeats {
			icsRepeats = append(icsRepeats, r.file+" "+rep)
		}
	}
	repeatNote := "No proof repeats another."
	if len(icsRepeats) > 0 {
		repeatNote = "The generator drew some keys twice, so these cases repeat an earlier one apart from the name: " + strings.Join(icsRepeats, "; ") + "."
	}
	var s strings.Builder
	fmt.Fprintf(&s, "Data-only fixture from production transparency logs and their published test data, held to transparency-dev/merkle v0.0.2 (proof.VerifyInclusion, rfc6962 hasher, compact.Range roots) and to an independent RFC 9162 section 2.1 reference in the checking program. 'valid' is transparency-dev/merkle's verdict; %s ", rfcAgreement(b))
	fmt.Fprintf(&s, "(1) sigstore-go v1.3.0 test bundles: sigstore.js@2.0.0-provenance is a real public-good Rekor entry (rekor.sigstore.dev, entry logIndex 31821305, which is shard-local proof index 27,657,874 in a tree of 27,657,875: the last leaf, so all 10 path elements are left siblings); othername is from a local sigstore scaffolding Rekor (index 3 of 4). Each root is the root in the bundle's signed checkpoint, whose ECDSA P-256 signature the program verifies with the Rekor key from sigstore-go's trusted-roots test data (key hint and logId checked). The leaf is SHA-256(0x00 || canonicalizedBody); the full bodies are in hash_checks. ")
	fmt.Fprintf(&s, "(2) rekor v1.5.4 pkg/verify/verify_test.go: TestInclusion's valid proof and its 'bad body hash' corruption, plus TestConsistency's size 1 and size 2 roots, held as trees and a node hash; the valid body's leaf hash is itself published there as the 1-to-2 consistency proof. TestInclusion's third case ('body not string') is a type error, not Merkle data, and root0 (line 70) is a placeholder, not an MTH; both are left out. ")
	fmt.Fprintf(&s, "(3) The transparency-dev golden log: tessera v1.0.4 testdata/log and serverless-log testdata/log are the same 15 leaves (build_log.sh, written with echo -n, so each leaf is exactly the word) signed by two different Ed25519 note keys under two origins. The program verifies all 32 signed checkpoints with transparency-dev/formats log.ParseCheckpoint and golang.org/x/mod note verifiers, confirms both logs give the same root at every size 0..15, confirms the leaf data three ways (tessera entry bundles tile/entries/000.p/1..15 parsed with tessera api.EntryBundle, serverless-log seq/ files, and serverless-log leaves/<leaf hash> index files), and confirms the leaf hashes against tessera's level-0 hash tiles (api.HashTile). serverless-log's tiles (api.Tile) also publish every complete internal node of the 15-leaf tree; those 11 are node hash checks. checkpoint.0 is the empty root. ")
	fmt.Fprintf(&s, "(4) ics23 testdata/tendermint (8 files, 67 existence proofs: 3 exist, 4 neighbors of 3 non-existence proofs, 20 batch items, 40 neighbors of 20 batch non-existence items) generated by confio/proofs-tendermint from tendermint v0.33.2 SimpleProofsFromMap. ics23 has no index or size: tree_size is the generator's claim (its Makefile testgen sizes), and leaf_index is derived from the inner-op sides at that size; at the claimed size every index is unique, sorted keys get strictly increasing indexes, non-existence neighbors are adjacent, and exist_left/exist_right land on 0 and n-1. Scanning sizes 1..%d, the vectors alone allow: %s. Upstream tests assert 10 of the 67 (TestVectors for the six single files, TestBatchVectors for batch_exist item 10 and batch_nonexist item 3); the other 57 have upstream_expectation 'none', although ics23 verifies all %d batch items. %s Upstream's 'tm invalid 1/2' cases are spec and key mismatches, not Merkle corruptions, and are left out, as are the op-level files testdata/TestLeafOpData.json, TestInnerOpData.json and TestDoHashData.json, which have no 0x00/0x01-prefixed RFC 6962 cases. ", ics23SizeScan, strings.Join(icsFits, "; "), b.icsBatchItemsVerified, repeatNote)
	fmt.Fprintf(&s, "(5) rekor-tiles v0.1.11 (Rekor v2) pkg/verify/verify_test.go:32-110 TestVerifyInclusionProof: its valid case and its three negatives ('invalid hash', path[0] with its first byte 0x59 set to 0x00; 'inclusion index beyond log size', checkpoint size 1; 'wrong proof size', checkpoint size 3 with a 1-hash path), all asserted by wantErr. rekor-tiles pkg/verify/verify.go:30-40 verifies with the entry's LogIndex (1) and the checkpoint's size and root, not the InclusionProof's own index and size, so those are the values used. The literals are rekor v1's two-entry log: hash = TestConsistency root1, rootHash = root2, and the body is TestInclusion's valid body. ")
	fmt.Fprintf(&s, "(6) sigstore-conformance at commit %s (no tag contains it; the repository has no LICENSE file and its README.md:139-141 states Apache 2.0): the %d test/assets/bundle-verify directories whose bundle carries an inclusion proof (%d proofs, %d distinct; tree sizes up to 1,340,288,195; Rekor v1 hashedrekord, dsse and intoto entries from production, staging and local logs, and Rekor v2 hashedrekord 0.0.2 entries). The suite's rule is that a directory ending in _fail must fail verification as a whole, for the reason in its README, and most of those reasons are not the Merkle proof. So each directory's expectation was set from its README: 'valid' for the directories without _fail (a conforming client verifies the inclusion proof, so it must verify), 'invalid' for inclusion-proof-corrupted-hash_fail and invalid-inclusion-proof_fail, whose READMEs name the inclusion proof, and 'none' for the other _fail directories, whose case names give the README's reason. Some 'none' proofs are invalid anyway because the bundle's entry was edited (bundle-empty-certificate-chain_fail, bundle-invalid-base64-signature_fail, incorrect-public-key_fail). Each root is the inclusion proof's rootHash; the checkpoint text is parsed with transparency-dev/formats and compared, and for production Rekor v1 entries its ECDSA signature is checked with the production key from sigstore-go's public-good trusted root (%d verify, %d do not, as the checkpoint-bad-keyhint and invalid-checkpoint-signature READMEs require; Rekor v2, staging and local log keys are not vendored, so those signatures are not checked). checkpoint-wrong-roothash_fail adds %d case checked against the checkpoint's own size and root, upstream 'invalid'. The leaf is rfc6962 HashLeaf(canonicalizedBody); the %d distinct bodies are leaf hash checks. Not vendored: %s. ",
		conformanceCommit, conf.dirs, conf.entries, conf.distinct, conf.sigVerified, conf.sigRejected, conf.cpCases, conf.bodies, strings.Join(conformanceOmitted, "; "))
	fmt.Fprintf(&s, "(7) Generated cases (names start with '%s'): for each of the %d published proofs that verify and do not repeat an earlier published proof exactly, the path cut short by one element with the root recomputed from the rest, and the path extended by one element (its own leaf hash) as a left or a right sibling with the root recomputed. They target RFC 9162's exact path length at real sizes up to 1,340,288,195, including right-edge proofs (sigstore.js, exist_right, nonexist_right, the Rekor v2 last-leaf proofs). ", genPrefix, countValidPublished(b))
	fmt.Fprintf(&s, "Other literals in these modules were examined and left out because they are not Merkle data with leaves: sigstore-go pkg/tlog/entry_test.go, pkg/sign/transparency_test.go and pkg/bundle/bundle_test.go use placeholder roots (\"deadbeef\", a hex string stored as bytes) with no leaves; tessera internal/parse/parse_test.go parses an unsigned checkpoint with no leaves; examples/bundle-publish.json and examples/bundle-provenance.json in sigstore-go have no inclusion proof (inclusionPromise only); rekor's TestConsistency other cases and TestCheckpoint are consistency or signature checks. ")
	fmt.Fprintf(&s, "Layout: in the truestamp-merkle-elixir repository this file is vectors/interop/production-logs.json and the checking program is the Go module in interop/go/production-logs/. Reproduce, from interop/go/production-logs/: go run . -fixtures ../../../vectors/interop/production-logs.json (check), or go run . -fixtures ../../../vectors/interop/production-logs.json -write (regenerate from the vendored upstream files, then check); -fixtures is required, and -ours ../../../vectors/merkle.json also checks the library's own vectors. The program reads only its own module directory (testdata/ and the LICENSE-* files are compiled in with go:embed and pinned by SHA-256; NOTICE lists every source's module, version and license and every vendored file) and the -fixtures path (and the -ours path, when given). The check re-derives every value with transparency-dev/merkle and the RFC reference and requires the file to equal the regenerated bytes.")
	return s.String()
}

func rfcAgreement(b *builder) string {
	n := 0
	for _, inc := range b.f.Inclusion {
		if inc.RFC9162Valid != nil {
			n++
		}
	}
	if n == 0 {
		return "the RFC reference agrees on every case, so no case carries rfc9162_valid."
	}
	return fmt.Sprintf("the RFC reference disagrees on %d cases, which carry rfc9162_valid and are listed under discrepancies.", n)
}

func countValidPublished(b *builder) int {
	n := 0
	for _, p := range b.published {
		if p.inc.Valid && len(p.path) > 0 && !p.noGen {
			n++
		}
	}
	return n
}

func sources() []string {
	return []string{
		"github.com/sigstore/sigstore-go@v1.3.0 (Apache-2.0) pkg/testing/data/bundles/sigstore.js@2.0.0-provenance.sigstore.json:12-46 tlogEntries[0]: public-good Rekor intoto entry (canonicalizedBody, inclusionProof logIndex 27657874, treeSize 27657875, 10 hashes, rootHash, signed checkpoint)",
		"github.com/sigstore/sigstore-go@v1.3.0 (Apache-2.0) pkg/testing/data/bundles/othername.sigstore.json:8-34 tlogEntries[0]: scaffolding Rekor hashedrekord entry (inclusionProof logIndex 3, treeSize 4, 2 hashes, rootHash, signed checkpoint)",
		"github.com/sigstore/sigstore-go@v1.3.0 (Apache-2.0) pkg/testing/data/trusted-roots/public-good.json:4-17 and scaffolding.json:4-17 tlogs[0]: Rekor ECDSA P-256 public keys and logIds (checkpoint signature check)",
		"github.com/sigstore/sigstore-go@v1.3.0 (Apache-2.0) pkg/verify/signed_entity_test.go:106-131 TestEntitySignedByPublicGoodWithTlogVerifiesSuccessfully and :230-254 TestEntityWithOthernameSan: both bundles verify with WithTransparencyLog(1) (upstream expectation valid)",
		"github.com/sigstore/sigstore-go@v1.3.0 (Apache-2.0) pkg/verify/tlog.go:112-123 and pkg/tlog/entry.go:466-501: an entry's inclusion proof goes to rekor pkg/verify VerifyInclusion and VerifyCheckpointSignature",
		"github.com/sigstore/rekor@v1.5.4 (Apache-2.0) pkg/verify/verify.go:137-177 VerifyInclusion: leaf = rfc6962 HashLeaf(body), then transparency-dev/merkle proof.VerifyInclusion",
		"github.com/sigstore/rekor@v1.5.4 (Apache-2.0) pkg/verify/verify_test.go:189-271 TestInclusion: 'valid inclusion' (lines 197-217) and 'invalid inclusion - bad body hash' (lines 218-238), index 1, size 2, one hash",
		"github.com/sigstore/rekor@v1.5.4 (Apache-2.0) pkg/verify/verify_test.go:66-71,93-106 TestConsistency: root1 (size 1), root2 (size 2), and the 1-to-2 consistency proof [leaf hash of entry 1]",
		"github.com/sigstore/rekor@v1.5.4 (Apache-2.0) pkg/util/signed_note.go:74-115,150-200 signed checkpoint format and ECDSA verification (reimplemented with the Go standard library for the sigstore-go checkpoints)",
		"github.com/transparency-dev/tessera@v1.0.4 (Apache-2.0) testdata/build_log.sh:10-25: golden log key, leaves one..fivten, one checkpoint per size",
		"github.com/transparency-dev/tessera@v1.0.4 (Apache-2.0) testdata/log/checkpoint.0..checkpoint.15 (and checkpoint = checkpoint.15): signed roots for sizes 0..15",
		"github.com/transparency-dev/tessera@v1.0.4 (Apache-2.0) testdata/log/tile/entries/000.p/1..15 entry bundles and testdata/log/tile/0/000.p/1..15 level-0 hash tiles, parsed with api/state.go:33-93 HashTile and EntryBundle",
		"github.com/transparency-dev/tessera@v1.0.4 (Apache-2.0) internal/witness/witness_test.go:588-600 loadCheckpoint: how tessera's own tests parse checkpoint.N (origin = key name)",
		"github.com/transparency-dev/serverless-log@v0.0.0-20260922103222-068d1cc47e5e (Apache-2.0) testdata/log.go:31-36 TestLogPublicKey and TestLogOrigin; testdata/build_log.sh:7-25",
		"github.com/transparency-dev/serverless-log@v0.0.0-20260922103222-068d1cc47e5e (Apache-2.0) testdata/log/checkpoint.0..checkpoint.15, seq/00/00/00/00/00..0e, leaves/*, tile/00/0000/00/00/00.01..00.0f, parsed with api/state.go:26-92 Tile and TileNodeKey and api/layout/paths.go:36-104",
		"github.com/transparency-dev/serverless-log@v0.0.0-20260922103222-068d1cc47e5e (Apache-2.0) client/client_test.go:51-73 mustLoadTestCheckpoints: how serverless-log's own tests parse checkpoint.N",
		"github.com/cosmos/ics23 tag go/v0.11.0, commit 16ead2358595639df8ee8c31306ac0eeda2e904f (Apache-2.0) testdata/tendermint/{exist_left,exist_middle,exist_right,nonexist_left,nonexist_middle,nonexist_right,batch_exist,batch_nonexist}.json: 8 roots, 67 existence proofs",
		"github.com/cosmos/ics23/go@v0.11.0 (Apache-2.0) go/vectors_data_test.go:32-57,76-150 and go/vectors_test.go:9-75 TestVectors and TestBatchVectors (upstream assertions)",
		"github.com/cosmos/ics23/go@v0.11.0 (Apache-2.0) go/proof.go:28-44 TendermintSpec, :108-131 ExistenceProof.Verify; go/ops.go:60-93 LeafOp.Apply and InnerOp.Apply; go/compress.go:26-36 Decompress (all used)",
		"github.com/confio/proofs-tendermint@v0.6.1 (no LICENSE file in the module; only numbers cited) Makefile:14-24 testgen tree sizes 987, 812, 1261, 813, 691, 1535, 1801, 1807; helpers/helpers.go:62-103 key choice; create.go:91-104 proofs from tendermint v0.33.2 SimpleProofsFromMap",
		"github.com/sigstore/rekor-tiles@v0.1.11 (Apache-2.0) pkg/verify/verify_test.go:32-110 TestVerifyInclusionProof: hash (line 33), rootHash (line 34), body (line 35), the 'invalid hash' proof hash (line 61), the four cases (lines 43-90) and entry LogIndex 1 (line 99)",
		"github.com/sigstore/rekor-tiles@v0.1.11 (Apache-2.0) pkg/verify/verify.go:30-40 VerifyInclusionProof: leaf = rfc6962 HashLeaf(CanonicalizedBody), then transparency-dev/merkle proof.VerifyInclusion at the entry's LogIndex and the checkpoint's Size and Hash",
		"github.com/sigstore/sigstore-conformance commit 767b4a7316a1186f0a5b4387d877f51d2a33c59f (Apache 2.0 per README.md:139-141; no LICENSE file) test/assets/bundle-verify/README.md (the _fail rule) and, for each of 65 directories, bundle.sigstore.json verificationMaterial.tlogEntries[0] (canonicalizedBody, inclusionProof logIndex, treeSize, hashes, rootHash, checkpoint.envelope) and README (the reason a _fail directory fails)",
		"github.com/transparency-dev/formats@v0.1.1 (Apache-2.0) log/checkpoint.go:52-79 Checkpoint.Unmarshal (sigstore-conformance checkpoint text)",
		"github.com/transparency-dev/merkle@v0.0.2 (Apache-2.0) proof/verify.go:46-73 VerifyInclusion and RootFromInclusionProof (the verdict behind every 'valid'), :78-125 VerifyConsistency (rekor roots), rfc6962/rfc6962.go:43-68 EmptyRoot, HashLeaf, HashChildren, compact/range.go:53-141 (tree roots)",
	}
}

// buildBytes is the regenerated file, or nil when the upstream checks failed.
func buildBytes() ([]byte, *builder) {
	f, b := build()
	if len(b.errs) > 0 {
		return nil, b
	}
	out := canonical(f)
	if bytes.Contains(out, []byte(emDash)) {
		b.fail("the fixture contains an em dash")
		return nil, b
	}
	return out, b
}
