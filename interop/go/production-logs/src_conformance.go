// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains one sentence quoted from github.com/sigstore/sigstore-conformance at
// commit 767b4a7316a1186f0a5b4387d877f51d2a33c59f,
// test/assets/bundle-verify/README.md, and that suite's directory names (Apache
// 2.0 per its README.md:139-141; the repository has no LICENSE file). License
// text: LICENSE-sigstore-conformance; see NOTICE.

package main

// The Rekor inclusion proofs carried by the sigstore-conformance verification
// suite, github.com/sigstore/sigstore-conformance at commit 767b4a7 (no tag
// contains it), test/assets/bundle-verify/*/bundle.sigstore.json. The bundles
// and their README files are vendored byte for byte under
// testdata/sigstore-conformance (see NOTICE); no upstream code or literal is
// copied into this file. The repository has no LICENSE file; its README.md:139-141
// states that it is licensed under the Apache 2.0 License.
//
// The suite's rule (test/assets/bundle-verify/README.md) is per directory: a
// name ending in "_fail" means the whole bundle must fail to verify, for the
// reason its README gives. Most of those reasons are not the Merkle proof, so
// each directory's expectation for the inclusion proof is set by hand below,
// from its README.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	conformanceCommit = "767b4a7316a1186f0a5b4387d877f51d2a33c59f"
	conformanceDir    = "sigstore-conformance/test/assets/bundle-verify"
	// publicGoodRoot is the sigstore-go trusted root that carries the production
	// Rekor v1 key; the suite verifies against the production trust root unless a
	// directory has its own trusted_root.json.
	publicGoodRoot = "sigstore-go/pkg/testing/data/trusted-roots/public-good.json"
)

// Checkpoint requirements a directory's README implies (checked, not published).
const (
	cpAny          = ""
	cpSigBad       = "the checkpoint signature must not verify with the production Rekor key"
	cpDiffers      = "the checkpoint must parse and differ from the proof in size or root"
	cpUnparseable  = "the checkpoint must not parse"
	upstreamValidW = "a directory without the _fail suffix: upstream expects the bundle to verify, and a conforming client verifies the inclusion proof, so the proof must verify"
)

type conformanceExpectation struct {
	proof string // upstream expectation for the inclusion proof: valid, invalid or none
	why   string // the directory README's reason, paraphrased
	cp    string // checkpoint requirement (cp* constants)
	// cpCase, when set, adds a second case that checks the proof against the
	// checkpoint's own size and root, with this upstream expectation.
	cpCase string
}

// conformanceExpectations covers every vendored directory. Directories that
// were not vendored, because their bundle carries no inclusion proof or is not
// JSON, are listed in conformanceOmitted.
var conformanceExpectations = map[string]conformanceExpectation{
	"bundle-with-sct-with-extensions":          {"valid", upstreamValidW, cpAny, ""},
	"happy-path-intoto-in-dsse-v3":             {"valid", upstreamValidW, cpAny, ""},
	"happy-path-v0.1":                          {"valid", upstreamValidW, cpAny, ""},
	"happy-path-v0.2":                          {"valid", upstreamValidW, cpAny, ""},
	"happy-path-v0.3":                          {"valid", upstreamValidW, cpAny, ""},
	"happy-path-v0.3-new-mediaType":            {"valid", upstreamValidW, cpAny, ""},
	"intoto-with-custom-trust-root":            {"valid", upstreamValidW, cpAny, ""},
	"managed-key-and-trusted-root":             {"valid", upstreamValidW, cpAny, ""},
	"managed-key-happy-path":                   {"valid", upstreamValidW, cpAny, ""},
	"rekor2-checkpoint-cosigned":               {"valid", upstreamValidW, cpAny, ""},
	"rekor2-checkpoint-multiple-cosigs":        {"valid", upstreamValidW, cpAny, ""},
	"rekor2-checkpoint-origin-not-first":       {"valid", upstreamValidW, cpAny, ""},
	"rekor2-checkpoint-two-sigs-cosigned":      {"valid", upstreamValidW, cpAny, ""},
	"rekor2-checkpoint-two-sigs-from-origin":   {"valid", upstreamValidW, cpAny, ""},
	"rekor2-dsse-happy-path":                   {"valid", upstreamValidW, cpAny, ""},
	"rekor2-happy-path":                        {"valid", upstreamValidW, cpAny, ""},
	"rekor2-timestamp-with-embedded-cert":      {"valid", upstreamValidW, cpAny, ""},
	"rekor2-timestamp-with-expired-cert-chain": {"valid", upstreamValidW, cpAny, ""},
	"rekor2-timestamp-without-embedded-cert":   {"valid", upstreamValidW, cpAny, ""},
	"trust-root-tlog-validity-end-inclusive":   {"valid", upstreamValidW, cpAny, ""},
	"trust-root-tsa-validity-end-inclusive":    {"valid", upstreamValidW, cpAny, ""},

	"inclusion-proof-corrupted-hash_fail": {"invalid", "the README says a proof hash has a bit flip and the bundle must fail because the Merkle proof is invalid", cpAny, ""},
	"invalid-inclusion-proof_fail":        {"invalid", "the README says the inclusion proof is old and not valid for this entry", cpAny, ""},

	"bundle-empty-certificate-chain_fail":                       {"none", "the README's reason is the empty certificate chain; the entry was also cut down (1 hash, a 44-byte body, no checkpoint), so its proof does not verify either", cpAny, ""},
	"bundle-from-wrong-instance_fail":                           {"none", "the README's reason is that a staging bundle is checked against the production trust root; its Merkle proof is valid", cpAny, ""},
	"bundle-invalid-base64-signature_fail":                      {"none", "the README's reason is invalid base64 in the bundle signature; the entry body was also edited, so its leaf is not the logged one and the proof does not verify", cpAny, ""},
	"bundle-with-root-cert_fail":                                {"none", "the README's reason is a root certificate in the chain", cpAny, ""},
	"checkpoint-bad-keyhint_fail":                               {"none", "the README's reason is a checkpoint signature from the wrong log (key hint); the proof itself is valid", cpSigBad, ""},
	"checkpoint-wrong-roothash_fail":                            {"none", "the README's reason is a checkpoint that does not apply to this bundle (its root hash is wrong); the proof is valid against the proof's own rootHash", cpDiffers, "invalid"},
	"dsse-invalid-sig_fail":                                     {"none", "the README's reason is a wrong DSSE signature", cpAny, ""},
	"dsse-mismatch-envelope_fail":                               {"none", "the README's reason is a DSSE envelope that does not match the entry", cpAny, ""},
	"dsse-mismatch-sig_fail":                                    {"none", "the README's reason is a DSSE signature that does not match the entry", cpAny, ""},
	"incorrect-public-key_fail":                                 {"none", "the README's reason is a modified public key in the entry; the edited body is not the logged leaf, so the proof does not verify either", cpAny, ""},
	"integrated-time-in-future_fail":                            {"none", "the README's reason is an integrated time outside the certificate validity", cpAny, ""},
	"intoto-expired-certificate_fail":                           {"none", "the README's reason is a certificate outside the trusted root's validity window", cpAny, ""},
	"intoto-log-entry-mismatch_fail":                            {"none", "the README's reason is a log entry that does not match the signed artifact", cpAny, ""},
	"intoto-set-outside-signing-cert-validity_fail":             {"none", "the README's reason is a signed entry timestamp outside the certificate validity", cpAny, ""},
	"intoto-tsa-timestamp-outside-cert-validity_fail":           {"none", "the README's reason is a TSA timestamp outside the certificate validity", cpAny, ""},
	"invalid-checkpoint-signature_fail":                         {"none", "the README's reason is an invalid checkpoint signature; the proof itself is valid", cpSigBad, ""},
	"invalid-ct-key_fail":                                       {"none", "the directory has no README; its name gives an invalid CT key as the reason", cpAny, ""},
	"managed-key-no-key_fail":                                   {"none", "the README's reason is a key-signed bundle verified without the key", cpAny, ""},
	"managed-key-wrong-key_fail":                                {"none", "the README's reason is the wrong verification key", cpAny, ""},
	"message-digest-mismatch_fail":                              {"none", "the README's reason is a messageDigest that does not match the artifact", cpAny, ""},
	"rekor2-checkpoint-missing-log-signature_fail":              {"none", "the README's reason is a checkpoint with its log signature removed", cpAny, ""},
	"rekor2-checkpoint-missing-origin_fail":                     {"none", "the README's reason is a checkpoint with its origin line removed; the proof is valid against the proof's own rootHash", cpUnparseable, ""},
	"rekor2-checkpoint-missing-root-hash_fail":                  {"none", "the README's reason is a checkpoint with its root hash removed; the proof is valid against the proof's own rootHash", cpUnparseable, ""},
	"rekor2-checkpoint-missing-size_fail":                       {"none", "the README's reason is a checkpoint with its size removed; the proof is valid against the proof's own rootHash", cpUnparseable, ""},
	"rekor2-checkpoint-no-matching-signature_fail":              {"none", "the README's reason is a checkpoint signature identity that does not match the log", cpAny, ""},
	"rekor2-dsse-invalid-sig_fail":                              {"none", "the README's reason is a DSSE envelope signature made with a different key", cpAny, ""},
	"rekor2-dsse-mismatch-envelope_fail":                        {"none", "the README's reason is a DSSE envelope that is not the logged one", cpAny, ""},
	"rekor2-dsse-mismatch-sig_fail":                             {"none", "the README's reason is an envelope signature that is not the logged one", cpAny, ""},
	"rekor2-no-timestamp_fail":                                  {"none", "the README's reason is a Rekor v2 bundle with no TSA timestamp", cpAny, ""},
	"rekor2-timestamp-outside-trust-root-tsa-validity_fail":     {"none", "the README's reason is a TSA timestamp outside the trusted root's TSA validity", cpAny, ""},
	"rekor2-timestamp-outside-tsa-cert-validity_fail":           {"none", "the README's reason is a TSA timestamp outside the TSA certificate validity", cpAny, ""},
	"rekor2-timestamp-payload-mismatch_fail":                    {"none", "the README's reason is a TSA timestamp over a different signature", cpAny, ""},
	"rekor2-timestamp-untrusted-tsa-with-embedded-cert_fail":    {"none", "the README's reason is an untrusted TSA", cpAny, ""},
	"rekor2-timestamp-untrusted-tsa-without-embedded-cert_fail": {"none", "the README's reason is an untrusted TSA", cpAny, ""},
	"rekor2-timestamp-with-incorrect-time_fail":                 {"none", "the README's reason is a TSA time outside the signing certificate lifetime", cpAny, ""},
	"set-invalid-signature_fail":                                {"none", "the README's reason is an invalid signed entry timestamp signature", cpAny, ""},
	"signature-mismatch_fail":                                   {"none", "the README's reason is a wrong bundle signature", cpAny, ""},
	"trust-root-tlog-missing-validity-start_fail":               {"none", "the README's reason is a malformed trusted root (log key validity has no start)", cpAny, ""},
	"wrong-hashedrekord-artifact_fail":                          {"none", "the README's reason is the wrong artifact", cpAny, ""},
	"wrong-hashedrekord-cert-and-sig_fail":                      {"none", "the README's reason is the wrong certificate and signature in the entry", cpAny, ""},
	"wrong-hashedrekord-entry_fail":                             {"none", "the README's reason is an entry for a different artifact", cpAny, ""},
	"wrong-material_fail":                                       {"none", "the README's reason is the wrong artifact", cpAny, ""},
}

// conformanceOmitted lists the bundle-verify directories whose bundles were
// not vendored, with the reason.
var conformanceOmitted = []string{
	"bundle-malformed-json_fail (the bundle is not valid JSON)",
	"bundle-negative-log-index_fail (no inclusion proof)",
	"bundle-unknown-version_fail (no inclusion proof)",
	"intoto-missing-inclusion-proof_fail (no inclusion proof)",
	"rekor2-no-inclusion-proof_fail (no inclusion proof)",
}

type conformanceBundle struct {
	MediaType string `json:"mediaType"`
	sigstoreBundle
}

// splitNote returns the text of a signed note (up to and including the newline
// before the blank line that precedes the signatures).
func splitNote(env string) ([]byte, bool) {
	data := []byte(env)
	i := bytes.LastIndex(data, []byte("\n\n"))
	if i < 0 {
		return nil, false
	}
	return data[:i+1], true
}

type conformanceResult struct {
	dirs, entries, distinct, cpCases, sigVerified, sigRejected, bodies int
}

func (b *builder) conformance() conformanceResult {
	var res conformanceResult
	h := rfc6962.DefaultHasher

	// The production Rekor v1 key, from the sigstore-go trusted root.
	var tr trustedRoot
	var pgDER []byte
	var pgLogID string
	if err := json.Unmarshal(readVendored(publicGoodRoot), &tr); err != nil || len(tr.Tlogs) != 1 {
		b.fail("sigstore-go public-good.json: %v", err)
	} else {
		pgLogID = tr.Tlogs[0].LogID.KeyID
		var err error
		pgDER, err = base64.StdEncoding.DecodeString(tr.Tlogs[0].PublicKey.RawBytes)
		b.expect(err == nil, "public-good Rekor key does not decode: %v", err)
	}

	readme := string(readVendored(conformanceDir + "/README.md"))
	b.expect(strings.Contains(readme, `Name should end in "_fail" if the verification is expected to fail`), "bundle-verify/README.md no longer states the _fail rule")

	var dirs []string
	_ = fs.WalkDir(vendored, path.Join("testdata", conformanceDir), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && path.Base(p) == "bundle.sigstore.json" {
			dirs = append(dirs, path.Base(path.Dir(p)))
		}
		return nil
	})
	sort.Strings(dirs)
	seenDir := map[string]bool{}
	for _, d := range dirs {
		seenDir[d] = true
	}
	for d := range conformanceExpectations {
		b.expect(seenDir[d], "sigstore-conformance: expectation for %s, which is not vendored", d)
	}
	distinct := map[string]bool{}
	// Distinct entry bodies become leaf hash checks, named after the first
	// directory that carries each and listing the others.
	type bodyUse struct {
		body []byte
		desc string
		dirs []string
	}
	var bodies []*bodyUse
	bodyIndex := map[string]*bodyUse{}

	for _, dir := range dirs {
		res.dirs++
		exp, ok := conformanceExpectations[dir]
		if !ok {
			b.fail("sigstore-conformance: no expectation for vendored directory %s", dir)
			continue
		}
		failDir := strings.HasSuffix(dir, "_fail")
		b.expect(failDir || exp.proof == "valid", "sigstore-conformance %s: a directory without _fail must expect a valid proof", dir)
		b.expect(!failDir || exp.proof != "valid", "sigstore-conformance %s: a _fail directory cannot expect a valid proof", dir)
		if exp.proof == "invalid" {
			rd := strings.ToLower(string(readVendored(path.Join(conformanceDir, dir, "README"))))
			b.expect(strings.Contains(rd, "inclusion proof"), "sigstore-conformance %s: README does not mention the inclusion proof", dir)
		}

		file := path.Join(conformanceDir, dir, "bundle.sigstore.json")
		var bu conformanceBundle
		if err := json.Unmarshal(readVendored(file), &bu); err != nil {
			b.fail("sigstore-conformance %s: %v", dir, err)
			continue
		}
		for i, e := range bu.VerificationMaterial.TlogEntries {
			ip := e.InclusionProof
			if ip == nil {
				continue
			}
			res.entries++
			body, err1 := base64.StdEncoding.DecodeString(e.CanonicalizedBody)
			root, err2 := base64.StdEncoding.DecodeString(ip.RootHash)
			idx, err3 := strconv.ParseUint(ip.LogIndex, 10, 64)
			size, err4 := strconv.ParseUint(ip.TreeSize, 10, 64)
			if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(root) != 32 {
				b.fail("sigstore-conformance %s entry %d: bad fields %v %v %v %v (root %d bytes)", dir, i, err1, err2, err3, err4, len(root))
				continue
			}
			var p [][]byte
			for _, hs := range ip.Hashes {
				n, err := base64.StdEncoding.DecodeString(hs)
				if err != nil || len(n) != 32 {
					b.fail("sigstore-conformance %s entry %d: proof hash %q is not 32 bytes of base64", dir, i, hs)
				}
				p = append(p, n)
			}
			leaf := h.HashLeaf(body)
			b.expect(bytes.Equal(leaf, refLeaf(body)), "sigstore-conformance %s: leaf hash disagrees with the RFC reference", dir)
			if u, ok := bodyIndex[string(body)]; ok {
				u.dirs = append(u.dirs, dir)
			} else {
				u = &bodyUse{body, fmt.Sprintf("%s/bundle.sigstore.json tlogEntries[%d].canonicalizedBody (%s %s entry, %d bytes, base64-decoded)", dir, i, e.KindVersion.Kind, e.KindVersion.Version, len(body)), nil}
				bodyIndex[string(body)] = u
				bodies = append(bodies, u)
			}

			// The checkpoint: parsed with transparency-dev/formats (signatures not
			// needed for the text), then, for production Rekor v1 entries, its
			// ECDSA signature checked with the production key.
			var cp log.Checkpoint
			cpState := "absent"
			if ip.Checkpoint.Envelope != "" {
				cpState = "unparseable"
				if text, ok := splitNote(ip.Checkpoint.Envelope); ok {
					// Lines after the root (Rekor v1's "Timestamp: ...") are the
					// checkpoint's other content and are allowed.
					if _, err := cp.Unmarshal(text); err == nil {
						cpState = "differs"
						if cp.Size == size && bytes.Equal(cp.Hash, root) {
							cpState = "agrees"
						}
					}
				}
			}
			sigState := "signature not checked (the log key is not vendored)"
			sigOK := false
			if e.LogID.KeyID == pgLogID && pgDER != nil && (cpState == "agrees" || cpState == "differs") {
				_, _, _, err := verifyRekorCheckpoint(ip.Checkpoint.Envelope, pgDER)
				if err == nil {
					sigOK = true
					res.sigVerified++
					sigState = "signature verifies with the production Rekor key (sigstore-go trusted-roots/public-good.json)"
				} else {
					res.sigRejected++
					sigState = "signature does not verify with the production Rekor key: " + err.Error()
				}
			}
			switch exp.cp {
			case cpSigBad:
				b.expect(e.LogID.KeyID == pgLogID && !sigOK, "sigstore-conformance %s: %s", dir, cpSigBad)
			case cpDiffers:
				b.expect(cpState == "differs", "sigstore-conformance %s: %s", dir, cpDiffers)
			case cpUnparseable:
				b.expect(cpState == "unparseable", "sigstore-conformance %s: %s", dir, cpUnparseable)
			}
			if exp.proof == "valid" {
				b.expect(cpState == "agrees", "sigstore-conformance %s: a happy-path checkpoint does not agree with the proof (%s)", dir, cpState)
				b.expect(e.LogID.KeyID != pgLogID || sigOK, "sigstore-conformance %s: a happy-path production checkpoint does not verify", dir)
			}
			cpDesc := map[string]string{
				"absent":      "no checkpoint",
				"unparseable": "checkpoint text does not parse",
				"agrees":      fmt.Sprintf("checkpoint %q agrees", cp.Origin),
				"differs":     fmt.Sprintf("checkpoint %q has size %d and a different root %s", cp.Origin, cp.Size, hx(cp.Hash)),
			}[cpState]
			if cpState == "agrees" || cpState == "differs" {
				cpDesc += "; " + sigState
			}

			key := caseKey(leaf, idx, size, p, root)
			if !distinct[key] {
				distinct[key] = true
				res.distinct++
			}
			base := fmt.Sprintf("sigstore-conformance@%s test/assets/bundle-verify/%s/bundle.sigstore.json tlogEntries[%d]: %s %s entry, entry logIndex %s, proof index %d of tree size %d, %d hashes",
				conformanceCommit[:7], dir, i, e.KindVersion.Kind, e.KindVersion.Version, e.LogIndex, idx, size, len(p))
			b.addPublishedDedup(Inclusion{
				Name:                fmt.Sprintf("%s, root = inclusionProof.rootHash (%s); upstream %s: %s", base, cpDesc, exp.proof, exp.why),
				LeafHash:            hx(leaf),
				LeafIndex:           idx,
				TreeSize:            size,
				Path:                hxs(p),
				Root:                hx(root),
				UpstreamExpectation: exp.proof,
			})
			if exp.cpCase != "" && cpState == "differs" {
				res.cpCases++
				b.addPublishedDedup(Inclusion{
					Name:                fmt.Sprintf("%s, checked against the checkpoint's own size %d and root (%s); upstream %s: the README says this checkpoint's root hash is wrong for this bundle", base, cp.Size, cpDesc, exp.cpCase),
					LeafHash:            hx(leaf),
					LeafIndex:           idx,
					TreeSize:            cp.Size,
					Path:                hxs(p),
					Root:                hx(cp.Hash),
					UpstreamExpectation: exp.cpCase,
				})
			}
		}
	}
	for _, u := range bodies {
		also := ""
		if len(u.dirs) > 0 {
			also = "; the same body is in " + strings.Join(u.dirs, ", ")
		}
		b.f.HashChecks = append(b.f.HashChecks, HashCheck{
			Name:     fmt.Sprintf("sigstore-conformance@%s test/assets/bundle-verify/%s%s; hash computed with rfc6962 HashLeaf", conformanceCommit[:7], u.desc, also),
			Kind:     "leaf",
			InputHex: sp(hx(u.body)),
			Hash:     hx(h.HashLeaf(u.body)),
		})
	}
	res.bodies = len(bodies)
	return res
}
