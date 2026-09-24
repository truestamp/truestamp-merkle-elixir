// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains material adapted from github.com/cometbft/cometbft@v1.0.1
// (Apache-2.0): the assertion and corruption logic of the upstream tests in
// crypto/merkle, types, abci/types, state and internal/blocksync (tree_test.go,
// proof_test.go, rfc6962_test.go, tx_test.go, block_test.go,
// consensus_breakage_test.go, validator_set_test.go, results_test.go,
// part_set_test.go, types_test.go, store_test.go, msgs_test.go), each cited by
// file and line where it is used, and the refusal texts "unexpected inner
// hashes" and "expected at least one inner hash" from crypto/merkle/proof.go:215
// and 220, quoted in a fixture note. License text: LICENSE-cometbft. See NOTICE.

// Command cometbft-crypto-merkle builds and confirms the fixture file of
// published Merkle known answers for github.com/cometbft/cometbft/crypto/merkle
// v1.0.1, and optionally checks the truestamp_merkle library's own vectors with
// the same implementation. In the truestamp_merkle repository the program lives
// at interop/go/cometbft-crypto-merkle/ and its fixture at
// vectors/interop/cometbft-crypto-merkle.json. From the program directory:
//
//	go run . -fixtures ../../../vectors/interop/cometbft-crypto-merkle.json
//	go run . -fixtures ../../../vectors/interop/cometbft-crypto-merkle.json -write
//	go run . -fixtures ../../../vectors/interop/cometbft-crypto-merkle.json -ours ../../../vectors/merkle.json
//
// -fixtures is required; -ours, when given, must name a file; -write
// regenerates the fixture file, then confirms it. Success prints one line
// "OK fixtures github.com/cometbft/cometbft/crypto/merkle@v1.0.1: <counts>"
// and, with -ours, a second line
// "OK ours github.com/cometbft/cometbft/crypto/merkle@v1.0.1: <counts>". Each
// problem prints one line beginning "FAIL fixtures " or "FAIL ours " instead of
// the OK line concerned, and the exit status is 1. A bad command line (unknown
// flag, missing or empty value, positional argument) prints one line
// "FAIL usage: <reason>" and exits 1; -h prints the usage to stderr and exits
// 0. Nothing is read except the -fixtures and -ours paths (dependencies come
// from the Go module cache at build time), and only -write writes, to the
// -fixtures path.
//
// Confirmation of the fixture file has two halves, both must pass:
//  1. Regeneration: every upstream literal (upstream.go and upstream_extra.go,
//     with file:line) is checked against the implementation's own functions while
//     the fixture is rebuilt, and the rebuilt fixture must equal the file byte for
//     byte.
//  2. File-driven: every value read back from the file is re-checked against the
//     implementation (HashFromByteSlices, HashFromByteSlicesIterative,
//     ProofsFromByteSlices, Proof.Verify, and the verifier core it calls) and
//     against an independent RFC 9162 section 2.1 reference.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	abci "github.com/cometbft/cometbft/abci/types"
	bcproto "github.com/cometbft/cometbft/api/cometbft/blocksync/v1"
	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/crypto/merkle"
	sm "github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/types"
)

const (
	modulePath      = "github.com/cometbft/cometbft/crypto/merkle"
	modVersion      = "v1.0.1"
	modLicense      = "Apache-2.0"
	maxFixtureBytes = 1_500_000 // size budget for the fixture file
)

// ---------------------------------------------------------------------------
// Fixture schema
// ---------------------------------------------------------------------------

type HashCheck struct {
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	InputHex *string `json:"input_hex,omitempty"`
	Left     *string `json:"left,omitempty"`
	Right    *string `json:"right,omitempty"`
	Hash     string  `json:"hash"`
}

// LeafDataRule gives leaf i (first <= i < first + tree_size) the data
// encoding(i). No tree in this fixture uses one (none exceeds 1,000 leaves); the
// field is kept so the schema matches the other fixtures, and the file-driven
// check understands it.
type LeafDataRule struct {
	Encoding string `json:"encoding"`
	First    int64  `json:"first"`
}

type Tree struct {
	Name         string        `json:"name"`
	LeafData     []string      `json:"leaf_data"`
	LeafHashes   []string      `json:"leaf_hashes"`
	LeafDataRule *LeafDataRule `json:"leaf_data_rule"`
	TreeSize     int64         `json:"tree_size"`
	Root         string        `json:"root"`
}

type Inclusion struct {
	Name                string   `json:"name"`
	LeafHash            string   `json:"leaf_hash"`
	LeafIndex           int64    `json:"leaf_index"`
	TreeSize            int64    `json:"tree_size"`
	Path                []string `json:"path"`
	Root                string   `json:"root"`
	Valid               bool     `json:"valid"`
	RFC9162Valid        *bool    `json:"rfc9162_valid,omitempty"`
	UpstreamExpectation string   `json:"upstream_expectation"`
}

type Fixture struct {
	Implementation string      `json:"implementation"`
	Version        string      `json:"version"`
	License        string      `json:"license"`
	Sources        []string    `json:"sources"`
	EmptyRoot      *string     `json:"empty_root"`
	HashChecks     []HashCheck `json:"hash_checks"`
	Trees          []Tree      `json:"trees"`
	Inclusion      []Inclusion `json:"inclusion"`
	Deviations     []string    `json:"deviations"`
	Discrepancies  []string    `json:"discrepancies"`
	Notes          string      `json:"notes"`
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

type builder struct {
	fx          Fixture
	fails       []string
	checks      int
	txStats     map[string]int
	rfcAgree    int
	rfcDisagree int
	rfcOverride int
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func hxs(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = hx(b)
	}
	return out
}

// unhex decodes a hex literal compiled into this program (an upstream constant).
// Values read from a file go through confirmResult.hexField, which never panics.
func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func (b *builder) failf(format string, args ...any) {
	b.fails = append(b.fails, fmt.Sprintf(format, args...))
}

func (b *builder) eq(what string, got, want []byte) {
	b.checks++
	if !bytes.Equal(got, want) {
		b.failf("%s: got %x, want %x", what, got, want)
	}
}

func (b *builder) truth(what string, ok bool) {
	b.checks++
	if !ok {
		b.failf("%s", what)
	}
}

// addTree records a tree after confirming the root with every implementation
// code path that computes one. With writeData false the leaf data is not
// written (leaf_data null): the leaves are too large to carry, and the file
// holds the implementation's leaf hashes instead.
func (b *builder) addTree(name string, leafData [][]byte, root []byte, writeData bool) {
	lh := make([][]byte, len(leafData))
	for i, d := range leafData {
		lh[i] = cmtLeafHash(d)
		b.eq(name+": leaf hash via HashFromByteSlices single-leaf", merkle.HashFromByteSlices([][]byte{d}), lh[i])
		b.eq(name+": leaf hash vs RFC 9162 reference", rfcLeafHash(d), lh[i])
	}
	b.eq(name+": HashFromByteSlices", merkle.HashFromByteSlices(leafData), root)
	b.eq(name+": HashFromByteSlicesIterative", merkle.HashFromByteSlicesIterative(leafData), root)
	pr, _ := merkle.ProofsFromByteSlices(leafData)
	b.eq(name+": ProofsFromByteSlices root", pr, root)
	b.eq(name+": root from leaf hashes via getSplitPoint/innerHash", implRootFromLeafHashes(lh), root)
	b.eq(name+": RFC 9162 reference MTH", rfcMTHFromLeafHashes(lh), root)
	var ld []string
	if writeData {
		ld = hxs(leafData)
	}
	b.fx.Trees = append(b.fx.Trees, Tree{
		Name:       name,
		LeafData:   ld,
		LeafHashes: hxs(lh),
		TreeSize:   int64(len(leafData)),
		Root:       hx(root),
	})
}

type incl struct {
	name     string
	leafHash []byte
	leafData []byte // leaf data for the exported Proof.Verify, when known
	hasData  bool
	index    int64
	total    int64
	aunts    [][]byte
	root     []byte
	expect   string // "valid" | "invalid" | "none"
	// upstreamCall is the result of the exact call the upstream test makes, when
	// that call differs from the leaf-hash-level check (for example Verify with a
	// mutated leaf and the original LeafHash, or TxProof.Validate). It must equal
	// the leaf-hash-level answer.
	upstreamCall *bool
	// discrepancy, when set, is the full text recorded under "discrepancies" for
	// a case where upstream's expectation and the verifier's answer differ. It is
	// a build failure to set it on a case where they agree.
	discrepancy string
}

func boolp(v bool) *bool { return &v }

func (b *builder) addInclusion(c incl) {
	v, _ := implVerifyLeafHash(c.leafHash, c.index, c.total, c.aunts, c.root)
	r := rfcVerify(c.index, c.total, c.leafHash, c.aunts, c.root)
	var rfcValid *bool
	if v != r {
		b.rfcDisagree++
		rfcValid = boolp(r)
		b.fx.Discrepancies = append(b.fx.Discrepancies,
			fmt.Sprintf("%s: the implementation's verifier returns valid=%v, RFC 9162 section 2.1.3.2 returns %v (rfc9162_valid)", c.name, v, r))
	} else {
		b.rfcAgree++
	}
	if c.hasData {
		p := merkle.Proof{Total: c.total, Index: c.index, LeafHash: c.leafHash, Aunts: c.aunts}
		ev := p.Verify(c.root, c.leafData) == nil
		b.truth(fmt.Sprintf("%s: exported Proof.Verify says %v, verifier core says %v", c.name, ev, v), ev == v)
	}
	if c.upstreamCall != nil {
		b.truth(fmt.Sprintf("%s: upstream's own call says %v, leaf-hash-level verifier says %v", c.name, *c.upstreamCall, v), *c.upstreamCall == v)
	}
	if (c.expect == "valid" && !v) || (c.expect == "invalid" && v) {
		msg := c.discrepancy
		if msg == "" {
			msg = fmt.Sprintf("%s: upstream expects %s, the implementation's verifier returns valid=%v", c.name, c.expect, v)
		}
		b.fx.Discrepancies = append(b.fx.Discrepancies, msg)
		// Hold the library to the RFC answer on every discrepancy case.
		rfcValid = boolp(r)
	} else if c.discrepancy != "" {
		b.failf("%s: a discrepancy text was given, but upstream's expectation %q agrees with valid=%v", c.name, c.expect, v)
	}
	if rfcValid != nil {
		b.rfcOverride++
	}
	b.fx.Inclusion = append(b.fx.Inclusion, Inclusion{
		Name:                c.name,
		LeafHash:            hx(c.leafHash),
		LeafIndex:           c.index,
		TreeSize:            c.total,
		Path:                hxs(c.aunts),
		Root:                hx(c.root),
		Valid:               v,
		RFC9162Valid:        rfcValid,
		UpstreamExpectation: c.expect,
	})
}

// checkPath confirms a prover's aunts for leaf i equal RFC 9162 PATH(i, D[n]).
func (b *builder) checkPath(what string, i int, lh [][]byte, aunts [][]byte) {
	want := rfcPath(i, lh)
	b.truth(fmt.Sprintf("%s leaf %d: aunts equal RFC 9162 PATH (length %d vs %d)", what, i, len(aunts), len(want)), len(aunts) == len(want))
	for j := range want {
		if j < len(aunts) {
			b.eq(fmt.Sprintf("%s leaf %d: aunt %d vs RFC 9162 PATH", what, i, j), aunts[j], want[j])
		}
	}
}

// addAllProofs adds every proof ProofsFromByteSlices produces for leafData, after
// checking each path against RFC 9162 PATH(m, D[n]).
func (b *builder) addAllProofs(treeName string, leafData [][]byte, expect string) {
	root, proofs := merkle.ProofsFromByteSlices(leafData)
	lh := make([][]byte, len(leafData))
	for i, d := range leafData {
		lh[i] = cmtLeafHash(d)
	}
	for i, p := range proofs {
		b.truth(fmt.Sprintf("%s leaf %d: Proof.Total/Index", treeName, i), p.Total == int64(len(leafData)) && p.Index == int64(i))
		b.eq(fmt.Sprintf("%s leaf %d: Proof.LeafHash", treeName, i), p.LeafHash, lh[i])
		b.checkPath(treeName, i, lh, p.Aunts)
		b.addInclusion(incl{
			name:     fmt.Sprintf("generated: ProofsFromByteSlices over [%s], leaf %d of %d", treeName, i, len(leafData)),
			leafHash: p.LeafHash, leafData: leafData[i], hasData: true,
			index: p.Index, total: p.Total, aunts: p.Aunts, root: root, expect: expect,
		})
	}
}

// generated leaf data: item i = SHA-256("item-" + decimal i), i.e. types.Tx("item-i").Hash(),
// a 32-byte stand-in for upstream's random testItem(cmtrand.Bytes(tmhash.Size)).
func genItems(n int) (types.Txs, [][]byte) {
	txs := make(types.Txs, n)
	items := make([][]byte, n)
	for i := 0; i < n; i++ {
		txs[i] = types.Tx(fmt.Sprintf("item-%d", i))
		items[i] = txs[i].Hash()
	}
	return txs, items
}

func build() *builder {
	b := &builder{txStats: map[string]int{}}
	b.fx.Implementation = modulePath
	b.fx.Version = modVersion
	b.fx.License = modLicense
	b.fx.HashChecks = []HashCheck{}
	b.fx.Trees = []Tree{}
	b.fx.Inclusion = []Inclusion{}
	b.fx.Deviations = []string{}
	b.fx.Discrepancies = []string{}

	// --- split rule: tree_test.go:141-151 against getSplitPoint and RFC 9162 k.
	for _, sp := range upSplitPoints {
		got := cmtGetSplitPoint(sp.length)
		b.truth(fmt.Sprintf("getSplitPoint(%d) = %d, upstream table says %d", sp.length, got, sp.want), got == sp.want)
		if sp.length > 1 {
			b.truth(fmt.Sprintf("getSplitPoint(%d) = %d, RFC 9162 k = %d", sp.length, got, rfcSplit(int(sp.length))), got == int64(rfcSplit(int(sp.length))))
		}
	}
	for n := int64(2); n <= 4096; n++ {
		b.truth(fmt.Sprintf("getSplitPoint(%d) vs RFC 9162 k", n), cmtGetSplitPoint(n) == int64(rfcSplit(int(n))))
	}

	// --- empty tree root: every upstream literal must agree with every code path.
	empty := unhex(upRFC6962EmptyTree)
	b.eq("rfc6962_test.go:42 vs HashFromByteSlices(nil)", merkle.HashFromByteSlices(nil), empty)
	b.eq("rfc6962_test.go:42 vs HashFromByteSlices([][]byte{})", merkle.HashFromByteSlices([][]byte{}), empty)
	b.eq("rfc6962_test.go:42 vs HashFromByteSlicesIterative(nil)", merkle.HashFromByteSlicesIterative(nil), empty)
	b.eq("rfc6962_test.go:42 vs emptyHash()", cmtEmptyHash(), empty)
	er, eproofs := merkle.ProofsFromByteSlices([][]byte{})
	b.eq("tree_test.go:47 TestProof empty root", er, unhex(upTestProofEmptyRoot))
	b.truth("tree_test.go:48 TestProof empty proofs", len(eproofs) == 0)
	b.eq("block_test.go:211-215 emptyBytes vs (*Data)(nil).Hash()", (*types.Data)(nil).Hash(), upEmptyBytes)
	b.eq("block_test.go:211-215 emptyBytes vs new(Data).Hash()", new(types.Data).Hash(), upEmptyBytes)
	b.eq("validator_set_test.go:49-53 vs NewValidatorSet(nil).Hash()", types.NewValidatorSet(nil).Hash(), upEmptyValSetHash)
	b.eq("empty root vs RFC 9162 reference", rfcEmptyRoot(), empty)
	er2 := hx(empty)
	b.fx.EmptyRoot = &er2

	// --- hash checks: rfc6962_test.go:26-76.
	{
		in := ""
		h := unhex(upRFC6962EmptyLeaf)
		b.eq("rfc6962_test.go:50 empty leaf via leafHash", cmtLeafHash([]byte{}), h)
		b.eq("rfc6962_test.go:50 empty leaf via HashFromByteSlices", merkle.HashFromByteSlices([][]byte{{}}), h)
		b.eq("rfc6962_test.go:50 empty leaf vs RFC 9162", rfcLeafHash(nil), h)
		b.fx.HashChecks = append(b.fx.HashChecks, HashCheck{
			Name: "published: crypto/merkle/rfc6962_test.go:46-52 TestRFC6962Hasher 'RFC6962 Empty Leaf' (leaf data is the empty string, line 29)",
			Kind: "leaf", InputHex: &in, Hash: hx(h),
		})
	}
	{
		in := hx(upRFC6962LeafInput)
		h := unhex(upRFC6962Leaf)
		b.eq("rfc6962_test.go:56 leaf via leafHash", cmtLeafHash(upRFC6962LeafInput), h)
		b.eq("rfc6962_test.go:56 leaf via HashFromByteSlices", merkle.HashFromByteSlices([][]byte{upRFC6962LeafInput}), h)
		b.eq("rfc6962_test.go:56 leaf vs RFC 9162", rfcLeafHash(upRFC6962LeafInput), h)
		b.fx.HashChecks = append(b.fx.HashChecks, HashCheck{
			Name: "published: crypto/merkle/rfc6962_test.go:53-58 TestRFC6962Hasher 'RFC6962 Leaf' (leaf data \"L123456\", line 27)",
			Kind: "leaf", InputHex: &in, Hash: hx(h),
		})
	}
	{
		l, r := hx(upRFC6962NodeLeft), hx(upRFC6962NodeRight)
		h := unhex(upRFC6962Node)
		b.eq("rfc6962_test.go:62 node via innerHash", cmtInnerHash(upRFC6962NodeLeft, upRFC6962NodeRight), h)
		b.eq("rfc6962_test.go:62 node vs RFC 9162", rfcNodeHash(upRFC6962NodeLeft, upRFC6962NodeRight), h)
		b.fx.HashChecks = append(b.fx.HashChecks, HashCheck{
			Name: "published: crypto/merkle/rfc6962_test.go:59-64 TestRFC6962Hasher 'RFC6962 Node' (children are the 4-byte strings \"N123\" and \"N456\", not 32-byte hashes)",
			Kind: "node", Left: &l, Right: &r, Hash: hx(h),
		})
	}

	// --- published trees: tree_test.go:21-42.
	for _, tc := range upHashFromByteSlicesCases {
		b.addTree(fmt.Sprintf("published: crypto/merkle/tree_test.go:%s TestHashFromByteSlices '%s'", tc.lines, tc.name), tc.slices, unhex(tc.expectHash), true)
	}

	// --- published trees: types/block_test.go:312-392 TestHeaderHash.
	{
		h := upTestHeader()
		leaves := upHeaderByteSlices(h)
		want := unhex(upTestHeaderHash)
		b.eq("block_test.go:333 vs Header.Hash()", h.Hash(), want)
		b.truth("block_test.go TestHeaderHash has 14 leaves", len(leaves) == 14)
		b.addTree("published: types/block_test.go:318-333 TestHeaderHash 'Generates expected hash' (leaf data = the 14 header field encodings built by block_test.go:359-387; root is the literal at line 333)", leaves, want, true)
	}

	// --- published trees: types/consensus_breakage_test.go.
	{
		vset := deterministicValidatorSet()
		leaves := make([][]byte, len(vset.Validators))
		for i, v := range vset.Validators {
			leaves[i] = v.Bytes() // validator_set.go:378-384 ValidatorSet.Hash
		}
		b.eq("consensus_breakage_test.go:19 vs ValidatorSet.Hash()", vset.Hash(), upValidatorsHash)
		b.addTree("published: types/consensus_breakage_test.go:17-20 TestValidatorsHash (leaf data = Validator.Bytes() of deterministicValidatorSet, lines 111-119)", leaves, upValidatorsHash, true)
	}
	{
		c := deterministicLastCommit()
		leaves := make([][]byte, len(c.Signatures))
		for i := range c.Signatures {
			bz, err := c.Signatures[i].ToProto().Marshal() // block.go:976-983 Commit.Hash
			must(err)
			leaves[i] = bz
		}
		b.eq("consensus_breakage_test.go:25 vs Commit.Hash()", c.Hash(), upLastCommitHash)
		b.addTree("published: types/consensus_breakage_test.go:23-26 TestLastCommitHash (leaf data = CommitSig protobuf encodings of deterministicLastCommit, lines 121-144)", leaves, upLastCommitHash, true)
	}
	{
		leaves := make([][]byte, len(upDataHashTxs))
		for i, tx := range upDataHashTxs {
			leaves[i] = tx.Hash() // tx.go:47-50, 83-89 Txs.Hash: leaves are SHA-256(tx)
		}
		b.eq("consensus_breakage_test.go:42 vs Data.Hash()", (&types.Data{Txs: upDataHashTxs}).Hash(), upDataHash)
		b.addTree("published: types/consensus_breakage_test.go:35-43 TestDataHash (leaf data = SHA-256(0x010203), the 32-byte tx hash)", leaves, upDataHash, true)
	}
	{
		evl := upEvidenceList()
		leaves := make([][]byte, len(evl))
		for i, ev := range evl {
			leaves[i] = ev.Bytes() // evidence.go:458-469 EvidenceList.Hash
		}
		b.eq("consensus_breakage_test.go:77 vs EvidenceList.Hash()", evl.Hash(), upEvidenceListHash)
		b.addTree("published: types/consensus_breakage_test.go:46-78 TestEvidenceHash EvidenceList (leaf data = Evidence.Bytes() of the DuplicateVoteEvidence and LightClientAttackEvidence built at lines 47-76)", leaves, upEvidenceListHash, true)
	}

	// --- published tree: internal/blocksync/msgs_test.go:80-103, the Header's
	//     DataHash inside the golden BlockResponse encoding.
	{
		golden := unhex(upBlocksyncBlockResponseHex)
		b.eq("msgs_test.go:103 golden encoding reproduced by msgs_test.go:81-85,101-102,135 (MakeBlock, ToProto, proto.Marshal)", upBlocksyncBlockResponse(), golden)
		var msg bcproto.Message
		must(msg.Unmarshal(golden))
		br := msg.GetBlockResponse()
		b.truth("msgs_test.go:103 decodes as a BlockResponse with a Block", br != nil && br.Block != nil)
		dataHash := br.Block.Header.DataHash
		b.truth("msgs_test.go:103 data_hash is 32 bytes and appears in the literal as tag 0x3a, length 0x20", len(dataHash) == 32 &&
			strings.Contains(upBlocksyncBlockResponseHex, "3a20"+hx(dataHash)))
		b.eq("msgs_test.go:103 evidence_hash (empty EvidenceList) vs empty root", br.Block.Header.EvidenceHash, empty)
		b.eq("msgs_test.go:103 evidence_hash vs EvidenceList(nil).Hash()", types.EvidenceList(nil).Hash(), br.Block.Header.EvidenceHash)
		txs := types.Txs(upBlocksyncTxs)
		b.eq("msgs_test.go:103 data_hash vs Txs{\"Hello World\"}.Hash()", txs.Hash(), dataHash)
		b.eq("msgs_test.go:103 data_hash vs (&Data{Txs}).Hash()", (&types.Data{Txs: txs}).Hash(), dataHash)
		leaves := [][]byte{txs[0].Hash()} // tx.go:45-50 Txs.Hash: leaves are SHA-256(tx)
		b.eq("msgs_test.go:81 leaf data vs SHA-256(\"Hello World\")", leaves[0], rfcSHA256([]byte("Hello World")))
		b.truth("msgs_test.go:81 Txs.Proof(0).Validate(data_hash)", txs.Proof(0).Validate(dataHash) == nil)
		b.addTree("published: internal/blocksync/msgs_test.go:80-103 TestBlocksyncMessageVectors 'BlockResponseMessage' (root = the Header.DataHash field inside the golden encoding at line 103, the Merkle root of Txs{\"Hello World\"} from line 81; leaf data = SHA-256(\"Hello World\"), the 32-byte tx hash)", leaves, dataHash, true)
		b.addAllProofs("internal/blocksync/msgs_test.go:81 Txs{\"Hello World\"}", leaves, "none")
	}

	// --- generated trees whose leaf data is an upstream literal but whose root is
	//     not hard-coded upstream.
	for _, pub := range upHashFromByteSlicesCases {
		if len(pub.slices) > 0 {
			b.addAllProofs(fmt.Sprintf("crypto/merkle/tree_test.go:%s '%s'", pub.lines, pub.name), pub.slices, "none")
		}
	}
	{
		h := upTestHeader()
		b.addAllProofs("types/block_test.go:318-333 TestHeaderHash header fields", upHeaderByteSlices(h), "none")
		vset := deterministicValidatorSet()
		vl := [][]byte{vset.Validators[0].Bytes()}
		b.addAllProofs("types/consensus_breakage_test.go:17-20 TestValidatorsHash", vl, "none")
		c := deterministicLastCommit()
		cl := make([][]byte, len(c.Signatures))
		for i := range c.Signatures {
			bz, err := c.Signatures[i].ToProto().Marshal()
			must(err)
			cl[i] = bz
		}
		b.addAllProofs("types/consensus_breakage_test.go:23-26 TestLastCommitHash", cl, "none")
		b.addAllProofs("types/consensus_breakage_test.go:35-43 TestDataHash", [][]byte{upDataHashTxs[0].Hash()}, "none")
		evl := upEvidenceList()
		b.addAllProofs("types/consensus_breakage_test.go:46-78 TestEvidenceHash EvidenceList", [][]byte{evl[0].Bytes(), evl[1].Bytes()}, "none")
	}

	// --- crypto/merkle/proof_test.go:142-179 TestProofValidateBasic.
	{
		leaves := upValidateBasicLeaves
		root, proofs := merkle.ProofsFromByteSlices(leaves)
		b.addTree("generated: crypto/merkle/proof_test.go:167-171 TestProofValidateBasic leaves [apple watermelon kiwi] (root not hard-coded upstream)", leaves, root, true)
		b.addAllProofs("crypto/merkle/proof_test.go:167-171 [apple watermelon kiwi]", leaves, "none")
		for _, m := range upValidateBasicMalleations {
			if m.name == "Good" {
				// Identical to the proofs[0] case already added; only confirm ValidateBasic.
				p := *proofs[0]
				b.truth("proof_test.go:148 'Good' ValidateBasic", p.ValidateBasic() == nil)
				continue
			}
			_, fresh := merkle.ProofsFromByteSlices(leaves)
			p := fresh[0]
			total, index, leafHash, aunts := p.Total, p.Index, p.LeafHash, append([][]byte{}, p.Aunts...)
			m.mutate(&total, &index, &leafHash, &aunts)
			mp := merkle.Proof{Total: total, Index: index, LeafHash: leafHash, Aunts: aunts}
			vbErr := mp.ValidateBasic()
			b.truth(fmt.Sprintf("proof_test.go:%s '%s' ValidateBasic error contains %q (got %v)", m.line, m.name, m.errStr, vbErr),
				vbErr != nil && strings.Contains(vbErr.Error(), m.errStr))
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: crypto/merkle/proof_test.go:%s TestProofValidateBasic '%s' applied to proofs[0] of [apple watermelon kiwi] (upstream_expectation is ValidateBasic's asserted error; valid is Verify's answer)", m.line, m.name),
				leafHash: leafHash, leafData: leaves[0], hasData: true,
				index: index, total: total, aunts: aunts, root: root, expect: "invalid",
			})
		}
	}

	// --- crypto/merkle/proof_test.go:210-231 TestVsa2022_100.
	{
		key, value, kvhash := upVsa2022100()
		op := merkle.NewValueOp(key, &merkle.Proof{LeafHash: kvhash})
		var nilRoot []byte
		err := merkle.ProofOperators{op}.Verify(nilRoot, "/"+string(key), [][]byte{value})
		b.truth("proof_test.go:230 TestVsa2022_100 must error", err != nil)
		// Confirm the copied kvhash construction against ValueOp.Run's own leaf
		// computation (proof_value.go:86-114): with Total 1 the run must succeed
		// and return kvhash as the single-leaf root.
		out, runErr := merkle.NewValueOp(key, &merkle.Proof{Total: 1, Index: 0, LeafHash: kvhash}).Run([][]byte{value})
		b.truth(fmt.Sprintf("TestVsa2022_100 kvhash matches ValueOp.Run (err %v)", runErr), runErr == nil && len(out) == 1 && bytes.Equal(out[0], kvhash))
		b.addInclusion(incl{
			name:     "generated: crypto/merkle/proof_test.go:210-231 TestVsa2022_100 forged membership proof (Total 0, Index 0, no aunts; upstream root is nil, written here as the empty string)",
			leafHash: kvhash, index: 0, total: 0, aunts: [][]byte{}, root: []byte{},
			expect: "invalid", upstreamCall: boolp(err == nil),
		})
	}

	// --- crypto/merkle/rfc6962_test.go:78-104 TestRFC6962HasherCollisions (inequalities only upstream).
	{
		h1 := merkle.HashFromByteSlices([][]byte{upCollisionLeaf1})
		h2 := merkle.HashFromByteSlices([][]byte{upCollisionLeaf2})
		b.truth("rfc6962_test.go:85 leaf hashes differ", !bytes.Equal(h1, h2))
		sub1 := merkle.HashFromByteSlices([][]byte{h1, h2})
		forged := merkle.HashFromByteSlices([][]byte{append(append([]byte{}, h1...), h2...)})
		sub2 := merkle.HashFromByteSlices([][]byte{h2, h1})
		b.truth("rfc6962_test.go:95 second-preimage", !bytes.Equal(sub1, forged))
		b.truth("rfc6962_test.go:101 order", !bytes.Equal(sub1, sub2))
		pre := "generated: crypto/merkle/rfc6962_test.go:78-104 TestRFC6962HasherCollisions "
		b.addTree(pre+"leaf1 [\"Hello\"] (upstream asserts only inequalities)", [][]byte{upCollisionLeaf1}, h1, true)
		b.addTree(pre+"leaf2 [\"World\"]", [][]byte{upCollisionLeaf2}, h2, true)
		b.addTree(pre+"subHash1 [hash1, hash2] (leaf DATA are the two leaf hashes)", [][]byte{h1, h2}, sub1, true)
		b.addTree(pre+"forgedHash [hash1 || hash2] (must differ from subHash1)", [][]byte{append(append([]byte{}, h1...), h2...)}, forged, true)
		b.addTree(pre+"subHash2 [hash2, hash1] (must differ from subHash1)", [][]byte{h2, h1}, sub2, true)
	}

	// --- types/tx_test.go:50-95 TestValidTxProof: the literal cases (lines 54-56),
	//     then the makeTxs cases (lines 57-59) over deterministic tx bytes.
	for _, tc := range upValidTxProofCases {
		b.validTxProof(fmt.Sprintf("types/tx_test.go:%s TestValidTxProof txs (leaf data = SHA-256(tx))", tc.line), tc.line, tc.txs)
	}
	for _, rc := range upValidTxProofRandomCases {
		label := fmt.Sprintf("cometbft types/tx_test.go TestValidTxProof makeTxs line %s", rc.line)
		txs := makeTxs(&detRand{label: label}, rc.cnt, rc.size)
		b.validTxProof(fmt.Sprintf("types/tx_test.go:%s TestValidTxProof makeTxs(%d, %d), tx bytes from the deterministic stream labeled %q (leaf data = SHA-256(tx))",
			rc.line, rc.cnt, rc.size, label), rc.line, txs)
	}

	// --- abci/types/types_test.go:13-45 TestHashAndProveResults.
	{
		trs := upExecTxResults()
		rs, err := abci.MarshalTxResults(trs)
		must(err)
		root := merkle.HashFromByteSlices(rs)
		_, proofs := merkle.ProofsFromByteSlices(rs)
		tname := "abci/types/types_test.go:14-33 TestHashAndProveResults ExecTxResults (leaf data = MarshalTxResults)"
		b.addTree("generated: "+tname+" (root not hard-coded upstream)", rs, root, true)
		for i, tr := range trs {
			bz, err := tr.Marshal()
			must(err)
			vErr := proofs[i].Verify(root, bz)
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: %s, proof %d (upstream asserts Verify succeeds, line 43)", tname, i),
				leafHash: proofs[i].LeafHash, leafData: rs[i], hasData: true,
				index: proofs[i].Index, total: proofs[i].Total, aunts: proofs[i].Aunts, root: root,
				expect: "valid", upstreamCall: boolp(vErr == nil),
			})
		}
	}

	// --- types/results_test.go:12-54 TestABCIResults.
	{
		results, a, bRes := upABCIResults()
		bzA, err := a.Marshal()
		must(err)
		bzB, err := bRes.Marshal()
		must(err)
		b.eq("results_test.go:26 a and b encode identically", bzA, bzB)
		b.eq("results_test.go:33 first encoding is empty", bzA, []byte{})
		leaves := make([][]byte, len(results))
		for i, res := range results {
			bz, err := res.Marshal()
			must(err)
			leaves[i] = bz
		}
		last := []byte{}
		for i, bz := range leaves[1:] {
			b.truth(fmt.Sprintf("results_test.go:38 result %d encodes differently from the previous one", i+1), !bytes.Equal(last, bz))
			last = bz
		}
		root := results.Hash()
		b.truth("results_test.go:44 NotEmpty(root)", len(root) > 0)
		tname := "types/results_test.go:12-54 TestABCIResults ABCIResults{a, c, d, e, f} from lines 13-18 and 29 (leaf data = ExecTxResult.Marshal(); leaf 0 is the empty string)"
		b.addTree("generated: "+tname+" (root not hard-coded upstream)", leaves, root, true)
		lh := hashLeaves(leaves)
		for i := range results {
			proof := results.ProveResult(i)
			b.checkPath("results_test.go", i, lh, proof.Aunts)
			vErr := proof.Verify(root, leaves[i])
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: %s, ProveResult(%d) (upstream asserts Verify succeeds, lines 50-52)", tname, i),
				leafHash: proof.LeafHash, leafData: leaves[i], hasData: true,
				index: proof.Index, total: proof.Total, aunts: proof.Aunts, root: root,
				expect: "valid", upstreamCall: boolp(vErr == nil),
			})
		}
	}

	// --- state/store_test.go:232-248 TestTxResultsHash.
	{
		txResults := upTxResultsHashInput()
		root := sm.TxResultsHash(txResults)
		results := types.NewResults(txResults)
		b.eq("store_test.go:241 TxResultsHash == NewResults(...).Hash()", results.Hash(), root)
		proof := results.ProveResult(0)
		bz, err := results[0].Marshal()
		must(err)
		b.truth("store_test.go:245 NewResults dropped the non-deterministic Log \"Huh?\" from the leaf", !bytes.Contains(bz, []byte("Huh?")))
		vErr := proof.Verify(root, bz)
		tname := "state/store_test.go:232-248 TestTxResultsHash [ExecTxResult{Code: 32, Data: \"Hello\", Log: \"Huh?\"}] from lines 233-235 (leaf data = NewResults(txResults)[0].Marshal(), which leaves out Log)"
		b.addTree("generated: "+tname+" (root not hard-coded upstream)", [][]byte{bz}, root, true)
		b.checkPath("store_test.go", 0, hashLeaves([][]byte{bz}), proof.Aunts)
		b.addInclusion(incl{
			name:     fmt.Sprintf("generated: %s, ProveResult(0) (upstream asserts Verify succeeds, line 247)", tname),
			leafHash: proof.LeafHash, leafData: bz, hasData: true,
			index: proof.Index, total: proof.Total, aunts: proof.Aunts, root: root,
			expect: "valid", upstreamCall: boolp(vErr == nil),
		})
	}

	// --- generated: every proof for tree sizes 1..16 over 32-byte items.
	for n := 1; n <= 16; n++ {
		txs, items := genItems(n)
		root := merkle.HashFromByteSlices(items)
		b.eq(fmt.Sprintf("items n=%d: Txs.Hash()", n), txs.Hash(), root)
		b.addTree(fmt.Sprintf("generated: items[0:%d], item i = SHA-256(\"item-\" + i)", n), items, root, true)
		for i := 0; i < n; i++ {
			b.truth(fmt.Sprintf("items n=%d: Txs.Proof(%d).Validate", n, i), txs.Proof(i).Validate(root) == nil)
		}
		b.addAllProofs(fmt.Sprintf("items[0:%d]", n), items, "none")
	}

	// --- crypto/merkle/tree_test.go:44-99 TestProof, total = 100, with its corruptions.
	{
		n := upTestProofTotal
		txs, items := genItems(n)
		rootHash := merkle.HashFromByteSlices(items)
		rootHash2, proofs := merkle.ProofsFromByteSlices(items)
		b.eq("tree_test.go:61 TestProof roots", rootHash2, rootHash)
		b.eq("TestProof stand-in: Txs.Hash()", txs.Hash(), rootHash)
		b.addTree("generated: crypto/merkle/tree_test.go:44-99 TestProof total=100, items[0:100] with item i = SHA-256(\"item-\" + i) standing in for cmtrand.Bytes(32)", items, rootHash, true)
		tname := "crypto/merkle/tree_test.go TestProof items[0:100]"
		r := &detRand{label: "cometbft crypto/merkle tree_test.go TestProof"}
		for i, item := range items {
			proof := proofs[i]
			vErr := proof.Verify(rootHash, item) // line 73
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: %s, proof %d (lines 73-74 assert Verify succeeds)", tname, i),
				leafHash: proof.LeafHash, leafData: item, hasData: true,
				index: proof.Index, total: proof.Total, aunts: proof.Aunts, root: rootHash,
				expect: "valid", upstreamCall: boolp(vErr == nil),
			})

			// "Trail too long should make it fail" (lines 76-80).
			origAunts := proof.Aunts
			long := append(append([][]byte{}, origAunts...), r.Bytes(32))
			lp := merkle.Proof{Total: proof.Total, Index: proof.Index, LeafHash: proof.LeafHash, Aunts: long}
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: %s, proof %d 'Trail too long' (lines 76-80)", tname, i),
				leafHash: proof.LeafHash, leafData: item, hasData: true,
				index: proof.Index, total: proof.Total, aunts: long, root: rootHash,
				expect: "invalid", upstreamCall: boolp(lp.Verify(rootHash, item) == nil),
			})

			// "Trail too short should make it fail" (lines 84-87).
			short := origAunts[0 : len(origAunts)-1]
			sp := merkle.Proof{Total: proof.Total, Index: proof.Index, LeafHash: proof.LeafHash, Aunts: short}
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: %s, proof %d 'Trail too short' (lines 84-87)", tname, i),
				leafHash: proof.LeafHash, leafData: item, hasData: true,
				index: proof.Index, total: proof.Total, aunts: short, root: rootHash,
				expect: "invalid", upstreamCall: boolp(sp.Verify(rootHash, item) == nil),
			})

			// "Mutating the itemHash should make it fail" (lines 91-93). Upstream keeps
			// the original LeafHash and passes the mutated item; at the leaf-hash level
			// the case is the mutated item's leaf hash with the original path and root.
			mutItem := mutateByteSlice(r, item)
			mlh := cmtLeafHash(mutItem)
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: %s, proof %d 'Mutating the itemHash' (lines 91-93, leaf data mutated)", tname, i),
				leafHash: mlh, leafData: mutItem, hasData: true,
				index: proof.Index, total: proof.Total, aunts: origAunts, root: rootHash,
				expect: "invalid", upstreamCall: boolp(proof.Verify(rootHash, mutItem) == nil),
			})

			// "Mutating the rootHash should make it fail" (lines 95-97).
			mutRoot := mutateByteSlice(r, rootHash)
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: %s, proof %d 'Mutating the rootHash' (lines 95-97)", tname, i),
				leafHash: proof.LeafHash, leafData: item, hasData: true,
				index: proof.Index, total: proof.Total, aunts: origAunts, root: mutRoot,
				expect: "invalid", upstreamCall: boolp(proof.Verify(mutRoot, item) == nil),
			})
		}
	}

	// --- types/part_set_test.go:19-65 TestBasicPartSet and 67-106 TestWrongProof.
	b.partSets()

	// --- types/tx_test.go:97-148 TestTxProofUnchangable, materialized over the
	//     TestValidTxProof literal proofs.
	b.txUnchangable()

	// --- strictness probes (not upstream cases).
	b.strictnessProbes()

	return b
}

// Deterministic stream labels standing in for cmtrand.Bytes(testPartSize * 100)
// in the two part-set tests (part_set_test.go:22 and :69).
const (
	basicPartSetLabel = "cometbft types/part_set_test.go TestBasicPartSet"
	wrongProofLabel   = "cometbft types/part_set_test.go TestWrongProof"
)

// partsOf splits data the way NewPartSetFromData does (part_set.go:191-221).
func partsOf(data []byte) [][]byte {
	n := (len(data) + upTestPartSize - 1) / upTestPartSize
	out := make([][]byte, n)
	for i := range out {
		out[i] = data[i*upTestPartSize : min((i+1)*upTestPartSize, len(data))]
	}
	return out
}

// partSets materializes github.com/cometbft/cometbft v1.0.1 (Apache-2.0)
// types/part_set_test.go TestBasicPartSet (19-65) and TestWrongProof (67-106). Each upstream test body runs against the
// implementation (upstream_extra.go); the parts exactly as passed to
// PartSet.AddPart are then written at the leaf-hash level.
func (b *builder) partSets() {
	b.truth("getSplitPoint(99) == getSplitPoint(100) == 64", cmtGetSplitPoint(99) == 64 && cmtGetSplitPoint(100) == 64)

	// TestBasicPartSet: every part is accepted by AddPart.
	{
		data := (&detRand{label: basicPartSetLabel}).Bytes(upTestPartSize * upPartSetParts)
		pristine := append([]byte(nil), data...)
		partSet, calls, checks := upTestBasicPartSet(data)
		for _, c := range checks {
			b.truth(c.what, c.ok)
		}
		b.eq("TestBasicPartSet leaves its data unchanged", data, pristine)
		root := partSet.Hash()
		parts := partsOf(pristine)
		lh := hashLeaves(parts)
		b.addTree(fmt.Sprintf("generated: types/part_set_test.go:19-65 TestBasicPartSet, NewPartSetFromData(data, testPartSize = 65536) over 100 parts; data = the first 6553600 bytes of the deterministic stream labeled %q (leaf_data omitted: each leaf is a 64 KiB part; root not hard-coded upstream)", basicPartSetLabel),
			parts, root, false)
		b.truth("TestBasicPartSet made 100 AddPart calls", len(calls) == upPartSetParts)
		for i, call := range calls {
			p := call.part
			b.eq(fmt.Sprintf("TestBasicPartSet part %d bytes", i), p.Bytes, parts[i])
			b.eq(fmt.Sprintf("TestBasicPartSet part %d Proof.LeafHash", i), p.Proof.LeafHash, lh[i])
			b.truth(fmt.Sprintf("TestBasicPartSet part %d Index/Proof.Index/Proof.Total", i),
				p.Index == uint32(i) && p.Proof.Index == int64(i) && p.Proof.Total == upPartSetParts)
			b.checkPath("part_set_test.go TestBasicPartSet", i, lh, p.Proof.Aunts)
			b.addInclusion(incl{
				name:     fmt.Sprintf("generated: types/part_set_test.go:37-44 TestBasicPartSet, part %d of 100 (upstream asserts PartSet.AddPart accepts it, lines 40-43)", i),
				leafHash: cmtLeafHash(p.Bytes), leafData: p.Bytes, hasData: true,
				index: p.Proof.Index, total: p.Proof.Total, aunts: p.Proof.Aunts, root: root,
				expect: "valid", upstreamCall: boolp(call.added && call.err == nil),
			})
		}
	}

	// TestWrongProof: four corruptions AddPart must reject.
	{
		data := (&detRand{label: wrongProofLabel}).Bytes(upTestPartSize * upPartSetParts)
		pristine := append([]byte(nil), data...)
		parts := partsOf(pristine)
		lh := hashLeaves(parts)
		partSet, calls := upTestWrongProof(data)
		root := partSet.Hash()
		b.eq("TestWrongProof root vs HashFromByteSlices over the unmodified parts", merkle.HashFromByteSlices(parts), root)
		b.addTree(fmt.Sprintf("generated: types/part_set_test.go:67-106 TestWrongProof, NewPartSetFromData(data, testPartSize = 65536) over 100 parts before the mutations; data = the first 6553600 bytes of the deterministic stream labeled %q (leaf_data omitted: each leaf is a 64 KiB part; root not hard-coded upstream)", wrongProofLabel),
			parts, root, false)
		if len(calls) != 4 {
			b.failf("TestWrongProof made %d AddPart calls, want 4", len(calls))
			return
		}
		// Upstream's own assertion holds: AddPart rejects all four.
		for _, call := range calls {
			b.truth(fmt.Sprintf("part_set_test.go:%s %q: AddPart returned added=%v err=%v", call.lines, call.desc, call.added, call.err), !call.added && call.err != nil)
		}
		// The mutations, as AddPart saw them. Flipping part 0's first aunt writes
		// into part 1's Proof.LeafHash too: FlattenAunts (proof.go:253-267) and
		// ProofsFromByteSlices (proof.go:62-75) hand out the same slice, the leaf
		// trail node's Hash.
		flipped := append([]byte(nil), lh[1]...)
		flipped[0]++
		b.eq("TestWrongProof 'bad trail': part 0 Aunts[0] is part 1's leaf hash with byte 0 + 1", calls[0].part.Proof.Aunts[0], flipped)
		b.eq("TestWrongProof 'bad bytes': part 1 Proof.LeafHash as passed to AddPart is already flipped (aliased to part 0 Aunts[0])", calls[1].part.Proof.LeafHash, flipped)
		badBytes := append([]byte(nil), parts[1]...)
		badBytes[0]++
		b.eq("TestWrongProof 'bad bytes': part 1 Bytes[0] + 1", calls[1].part.Bytes, badBytes)
		b.truth("TestWrongProof 'bad proof index': part 2 carries Proof.Index 1", calls[2].part.Index == 2 && calls[2].part.Proof.Index == 1 && calls[2].part.Proof.Total == upPartSetParts)
		b.truth("TestWrongProof 'bad proof total': part 3 carries Proof.Total 99", calls[3].part.Index == 3 && calls[3].part.Proof.Index == 3 && calls[3].part.Proof.Total == upPartSetParts-1)
		for _, k := range []int{0, 2, 3} {
			b.eq(fmt.Sprintf("TestWrongProof part %d bytes unchanged", k), calls[k].part.Bytes, parts[k])
		}

		names := []string{
			"generated: types/part_set_test.go:75-81 TestWrongProof 'bad trail': part 0 of 100 with Proof.Aunts[0][0] += 1 (upstream asserts PartSet.AddPart rejects it)",
			"generated: types/part_set_test.go:83-89 TestWrongProof 'bad bytes': part 1 of 100 with Bytes[0] += 1, leaf_hash = SHA-256(0x00 || mutated part) (upstream asserts PartSet.AddPart rejects it)",
			"generated: types/part_set_test.go:91-97 TestWrongProof 'bad proof index': part 2 of 100 presented with Proof.Index 1 (upstream asserts PartSet.AddPart rejects it)",
			"generated: types/part_set_test.go:99-105 TestWrongProof 'bad proof total': part 3 of 100 presented with Proof.Total 99 (upstream asserts PartSet.AddPart rejects it; Proof.Verify accepts it, see discrepancies)",
		}
		for k, call := range calls {
			p := call.part
			leafHash := cmtLeafHash(p.Bytes)
			v, _ := implVerifyLeafHash(leafHash, p.Proof.Index, p.Proof.Total, p.Proof.Aunts, root)
			ev := p.Proof.Verify(root, p.Bytes) == nil
			b.truth(fmt.Sprintf("%s: Proof.Verify on the proof exactly as passed to AddPart says %v, leaf-hash-level verifier says %v", names[k], ev, v), ev == v)
			disc := ""
			if k == 3 {
				r := rfcVerify(p.Proof.Index, p.Proof.Total, leafHash, p.Proof.Aunts, root)
				trace, traceOK := rfcFnSnTrace(uint64(p.Proof.Index), uint64(p.Proof.Total), len(p.Proof.Aunts))
				b.truth("TestWrongProof 'bad proof total': RFC 9162 section 2.1.3.2 index bookkeeping completes", traceOK)
				b.truth("TestWrongProof 'bad proof total': Proof.Verify accepts and RFC 9162 section 2.1.3.2 accepts", v && r)
				// A receiver whose header claims 99 parts, with the same hash, accepts part 3.
				p3 := snapshotPart(&calls[3].part)
				ps99 := types.NewPartSetFromHeader(types.PartSetHeader{Total: upPartSetParts - 1, Hash: root})
				added, err := ps99.AddPart(&p3)
				b.truth(fmt.Sprintf("TestWrongProof 'bad proof total': a PartSet whose header claims Total 99 with the same hash accepts part 3 (added=%v err=%v)", added, err), added && err == nil)
				disc = fmt.Sprintf("%s: upstream asserts that PartSet.AddPart rejects part 3 of a 100-part set presented with Proof.Total %d. AddPart does reject it, but with its own tree-size check (types/part_set.go:314-317, part.Proof.Total != ps.total) before any Merkle check (part_set.go:319-322). The implementation's verifier, Proof.Verify (crypto/merkle/proof.go:79-114, core computeHashFromAunts at 206-237), accepts the proof, so valid=true against upstream_expectation 'invalid'. RFC 9162 section 2.1.3.2 also accepts it (rfc9162_valid=%v, from the reference in rfc9162.go): with leaf_index %d and tree_size %d the (fn, sn) pairs run %s over the %d-element path, so sn reaches 0 exactly as the path ends, and the recomputed hash equals the 100-leaf root because leaf 3 lies in the left 64-leaf subtree under both sizes (getSplitPoint(99) = getSplitPoint(100) = 64) and the last path element is the right subtree's root, used as an opaque hash. A PartSet whose header claims Total 99 with the same hash accepts the part (checked). Neither the verifier nor the RFC algorithm binds tree_size beyond the shape of the path; it has to be authenticated separately, as AddPart does against its header.",
					names[k], p.Proof.Total, r, p.Proof.Index, p.Proof.Total, trace, len(p.Proof.Aunts))
			}
			b.addInclusion(incl{
				name:     names[k],
				leafHash: leafHash, leafData: p.Bytes, hasData: true,
				index: p.Proof.Index, total: p.Proof.Total, aunts: p.Proof.Aunts, root: root,
				expect: "invalid", discrepancy: disc,
			})
		}
	}
}

// validTxProof mirrors the body of TestValidTxProof (github.com/cometbft/cometbft
// v1.0.1 types/tx_test.go:62-94, Apache-2.0) for one case: every Txs.Proof(i) must Validate(root) and must not
// Validate([]byte("foobar")), and survives a protobuf round trip.
func (b *builder) validTxProof(tname, line string, txs types.Txs) {
	root := txs.Hash()
	leaves := make([][]byte, len(txs))
	for i := range txs {
		leaves[i] = txs[i].Hash()
	}
	b.addTree("generated: "+tname+" (root not hard-coded upstream)", leaves, root, true)
	for i := range txs {
		proof := txs.Proof(i)
		b.truth(fmt.Sprintf("tx_test.go:69-73 line %s proof %d Index/Total/RootHash/Data/Leaf", line, i),
			proof.Proof.Index == int64(i) && proof.Proof.Total == int64(len(txs)) && bytes.Equal(proof.RootHash, root) &&
				bytes.Equal(proof.Data, txs[i]) && bytes.Equal(proof.Leaf(), txs[i].Hash()))
		b.checkPath("tx_test.go line "+line, i, hashLeaves(leaves), proof.Proof.Aunts)
		vErr := proof.Validate(root)
		b.truth(fmt.Sprintf("tx_test.go:74 %s proof %d Validate(root)", line, i), vErr == nil)
		pbProof := proof.ToProto()
		bin, err := pbProof.Marshal()
		must(err)
		var pb2 cmtproto.TxProof
		must(pb2.Unmarshal(bin))
		p2, err := types.TxProofFromProto(pb2)
		b.truth(fmt.Sprintf("tx_test.go:77-92 line %s proof %d protobuf round trip validates", line, i), err == nil && p2.Validate(root) == nil)
		b.addInclusion(incl{
			name:     fmt.Sprintf("generated: %s, Txs.Proof(%d) (upstream asserts Validate(root) succeeds, tx_test.go:74)", tname, i),
			leafHash: proof.Proof.LeafHash, leafData: leaves[i], hasData: true,
			index: proof.Proof.Index, total: proof.Proof.Total, aunts: proof.Proof.Aunts, root: root,
			expect: "valid", upstreamCall: boolp(vErr == nil),
		})
		wErr := proof.Validate(upTxWrongDataHash)
		b.addInclusion(incl{
			name:     fmt.Sprintf("generated: %s, Txs.Proof(%d) checked against root \"foobar\" (tx_test.go:75 Validate([]byte(\"foobar\")))", tname, i),
			leafHash: proof.Proof.LeafHash, leafData: leaves[i], hasData: true,
			index: proof.Proof.Index, total: proof.Proof.Total, aunts: proof.Proof.Aunts, root: upTxWrongDataHash,
			expect: "invalid", upstreamCall: boolp(wErr == nil),
		})
	}
}

func hashLeaves(data [][]byte) [][]byte {
	lh := make([][]byte, len(data))
	for i, d := range data {
		lh[i] = cmtLeafHash(d)
	}
	return lh
}

// txUnchangable mirrors testTxProofUnchangable (github.com/cometbft/cometbft
// v1.0.1 types/tx_test.go:104-125, Apache-2.0) and assertBadProof
// (tx_test.go:128-148) over the literal TestValidTxProof proofs.
// A decoded mutation is written out as an inclusion case only when the
// leaf-hash-level question is exactly what TxProof.Validate decides: RootHash is
// still the good root and LeafHash is still SHA-256(0x00 || SHA-256(Data)).
// Everything else is counted in the notes.
func (b *builder) txUnchangable() {
	seen := map[string]bool{}
	for _, tc := range upValidTxProofCases {
		txs := tc.txs
		root := txs.Hash()
		for i := range txs {
			good := txs.Proof(i)
			b.truth("tx_test.go:113 good proof valid", good.Validate(root) == nil)
			pbProof := good.ToProto()
			bin, err := pbProof.Marshal()
			must(err)
			r := &detRand{label: fmt.Sprintf("cometbft types/tx_test.go TestTxProofUnchangable case line %s proof %d", tc.line, i)}
			for j := 0; j < upTxUnchangableMutations; j++ {
				bad := mutateByteSlice(r, bin)
				if bytes.Equal(bad, bin) {
					b.txStats["mutation equal to input (skipped upstream too)"]++
					continue
				}
				b.txStats["mutations"]++
				var pb cmtproto.TxProof
				if err := pb.Unmarshal(bad); err != nil {
					b.txStats["protobuf unmarshal error"]++
					continue
				}
				proof, err := types.TxProofFromProto(pb)
				if err != nil {
					b.txStats["rejected by ProofFromProto/ValidateBasic"]++
					continue
				}
				vErr := proof.Validate(root)
				if vErr == nil && proof.Proof.Total == good.Proof.Total {
					b.fx.Discrepancies = append(b.fx.Discrepancies, fmt.Sprintf(
						"types/tx_test.go:144 assertBadProof: mutation %d of case line %s proof %d validates with the same Total %d", j, tc.line, i, proof.Proof.Total))
				}
				if !bytes.Equal(proof.RootHash, root) {
					b.txStats["RootHash field changed (Validate rejects before Merkle verification)"]++
					b.truth("changed RootHash must not validate", vErr != nil)
					continue
				}
				if !bytes.Equal(proof.Proof.LeafHash, cmtLeafHash(proof.Data.Hash())) {
					b.txStats["Data and LeafHash no longer consistent (Proof.Verify leaf check rejects)"]++
					b.truth("inconsistent Data/LeafHash must not validate", vErr != nil)
					continue
				}
				same := proof.Proof.Index == good.Proof.Index && proof.Proof.Total == good.Proof.Total &&
					bytes.Equal(proof.Proof.LeafHash, good.Proof.LeafHash) && equalAunts(proof.Proof.Aunts, good.Proof.Aunts)
				if same {
					b.txStats["decoded to the original proof"]++
					continue
				}
				key := fmt.Sprintf("%x|%d|%d|%x|%s", proof.Proof.LeafHash, proof.Proof.Index, proof.Proof.Total, root, strings.Join(hxs(proof.Proof.Aunts), ","))
				if seen[key] {
					b.txStats["duplicate of an earlier representable mutation"]++
					continue
				}
				seen[key] = true
				b.txStats["representable at the leaf-hash level"]++
				var changed []string
				if proof.Proof.Index != good.Proof.Index {
					changed = append(changed, fmt.Sprintf("Index %d->%d", good.Proof.Index, proof.Proof.Index))
				}
				if proof.Proof.Total != good.Proof.Total {
					changed = append(changed, fmt.Sprintf("Total %d->%d", good.Proof.Total, proof.Proof.Total))
				}
				if !bytes.Equal(proof.Proof.LeafHash, good.Proof.LeafHash) {
					changed = append(changed, "Data and LeafHash")
				}
				if !equalAunts(proof.Proof.Aunts, good.Proof.Aunts) {
					changed = append(changed, fmt.Sprintf("Aunts (%d->%d)", len(good.Proof.Aunts), len(proof.Proof.Aunts)))
				}
				expect := "invalid"
				if proof.Proof.Total != good.Proof.Total {
					// tx_test.go:140-144: upstream tolerates acceptance when Total differs.
					expect = "none"
				}
				if vErr == nil {
					b.txStats["representable and accepted by Validate"]++
				}
				b.addInclusion(incl{
					name: fmt.Sprintf("generated: types/tx_test.go testTxProofUnchangable draw %d on TestValidTxProof line %s proof %d: %s changed",
						j, tc.line, i, strings.Join(changed, ", ")),
					leafHash: proof.Proof.LeafHash, leafData: proof.Data.Hash(), hasData: true,
					index: proof.Proof.Index, total: proof.Proof.Total, aunts: proof.Proof.Aunts, root: root,
					expect: expect, upstreamCall: boolp(vErr == nil),
				})
			}
		}
	}
}

func equalAunts(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func (b *builder) strictnessProbes() {
	_, items := genItems(5)
	root5, proofs5 := merkle.ProofsFromByteSlices(items)
	p4 := proofs5[4]
	b.addInclusion(incl{
		name:     "generated: strictness probe: proof of leaf 4 of items[0:5] with leaf_index raised to 5 (== tree_size)",
		leafHash: p4.LeafHash, leafData: items[4], hasData: true,
		index: 5, total: 5, aunts: p4.Aunts, root: root5, expect: "none",
	})

	_, items4 := genItems(4)
	root4, proofs4 := merkle.ProofsFromByteSlices(items4)
	b.addInclusion(incl{
		name:     "generated: strictness probe: valid proof of leaf 0 of items[0:4] presented with tree_size 3 (same path shape; neither this verifier nor RFC 9162 section 2.1.3.2 authenticates tree_size, cf. types/tx_test.go:140-144)",
		leafHash: proofs4[0].LeafHash, leafData: items4[0], hasData: true,
		index: 0, total: 3, aunts: proofs4[0].Aunts, root: root4, expect: "none",
	})
	b.addInclusion(incl{
		name:     "generated: strictness probe: valid proof of leaf 0 of items[0:4] presented with tree_size 2 (path one element too long for that size)",
		leafHash: proofs4[0].LeafHash, leafData: items4[0], hasData: true,
		index: 0, total: 2, aunts: proofs4[0].Aunts, root: root4, expect: "none",
	})

	_, items1 := genItems(1)
	root1, proofs1 := merkle.ProofsFromByteSlices(items1)
	extra := (&detRand{label: "cometbft strictness probe extra aunt"}).Bytes(32)
	b.addInclusion(incl{
		name:     "generated: strictness probe: single-leaf tree with one extra aunt",
		leafHash: proofs1[0].LeafHash, leafData: items1[0], hasData: true,
		index: 0, total: 1, aunts: [][]byte{extra}, root: root1, expect: "none",
	})
	b.addInclusion(incl{
		name:     "generated: strictness probe: tree_size 0, leaf_index 0, empty path, root = empty-tree root",
		leafHash: proofs1[0].LeafHash, leafData: items1[0], hasData: true,
		index: 0, total: 0, aunts: [][]byte{}, root: rfcEmptyRoot(), expect: "none",
	})
}

// ---------------------------------------------------------------------------
// Sources, deviations, notes
// ---------------------------------------------------------------------------

func (b *builder) finish() {
	b.fx.Sources = []string{
		"crypto/merkle/hash.go:10-44 leaf prefix 0x00, inner prefix 0x01, emptyHash = SHA-256(\"\")",
		"crypto/merkle/tree.go:9-27 HashFromByteSlices (recursive, split via getSplitPoint)",
		"crypto/merkle/tree.go:68-98 HashFromByteSlicesIterative (pairwise, odd last node promoted unchanged)",
		"crypto/merkle/tree.go:100-112 getSplitPoint (largest power of two strictly less than n)",
		"crypto/merkle/proof.go:53-75 Proof{Total, Index, LeafHash, Aunts} and ProofsFromByteSlices",
		"crypto/merkle/proof.go:79-114 Proof.Verify(rootHash, leaf DATA)",
		"crypto/merkle/proof.go:145-172 Proof.ValidateBasic (32-byte hashes, at most MaxAunts=100 aunts, non-negative Total/Index)",
		"crypto/merkle/proof.go:206-237 computeHashFromAunts (verifier core, exact path length, 0 <= index < total)",
		"crypto/merkle/proof.go:251-295 FlattenAunts / trailsFromByteSlicesInternal (aunt order: leaf's sibling first, root's child last)",
		"crypto/merkle/rfc6962_test.go:26-76 TestRFC6962Hasher: hard-coded empty tree, empty leaf, leaf \"L123456\", node N123/N456 (copied from Trillian)",
		"crypto/merkle/rfc6962_test.go:78-104 TestRFC6962HasherCollisions: inequality assertions only, no hard-coded hashes",
		"crypto/merkle/tree_test.go:21-42 TestHashFromByteSlices: hard-coded roots for nil, empty, single, single blank, two, many (5 leaves)",
		"crypto/merkle/tree_test.go:44-99 TestProof: hard-coded empty root (line 47); 100 random 32-byte items; corruptions trail too long, trail too short, mutated item, mutated root",
		"crypto/merkle/tree_test.go:101-112 TestHashAlternatives: recursive vs iterative on random items, no hard-coded values",
		"crypto/merkle/tree_test.go:136-157 Test_getSplitPoint: hard-coded split-point table",
		"crypto/merkle/proof_test.go:142-179 TestProofValidateBasic: malleations of proofs[0] of [apple watermelon kiwi]",
		"crypto/merkle/proof_test.go:181-208 TestVoteProtobuf: protobuf round trip only (not materialized, no root)",
		"crypto/merkle/proof_test.go:210-231 TestVsa2022_100: forged membership proof with Total 0 and a nil root",
		"libs/test/mutate.go:8-28 MutateByteSlice: corruption logic used by TestProof and TestTxProofUnchangable",
		"types/block_test.go:192-206 makeBlockID; 210-225 emptyBytes and TestNilDataHashDoesntCrash (empty Data hash = empty root)",
		"types/block_test.go:312-392 TestHeaderHash: hard-coded 14-leaf root F740121F... (line 333) with the leaf construction at 359-387",
		"types/encoding_helper.go:11-47 cdcEncode and types/utils.go:10-29 isTypedNil/isEmpty (unexported, copied for the header leaves)",
		"types/validator_set_test.go:23-53 TestValidatorSetBasic: empty validator set hash = empty root (lines 49-53)",
		"types/consensus_breakage_test.go:17-20 TestValidatorsHash, 23-26 TestLastCommitHash, 35-43 TestDataHash, 46-78 TestEvidenceHash: hard-coded Merkle roots (TestConsensusHash and the single-evidence hashes are plain SHA-256, not Merkle)",
		"types/consensus_breakage_test.go:111-167 deterministicValidatorSet, deterministicLastCommit, deterministicVote",
		"types/tx.go:47-161 Txs.Hash, Txs.Proof, TxProof.Validate (leaves are SHA-256(tx))",
		"types/tx_test.go:16-22 makeTxs; 50-95 TestValidTxProof: literal txs at lines 54-56 and makeTxs(20, 5), makeTxs(7, 81), makeTxs(61, 15) at lines 57-59; every proof must Validate, Validate(\"foobar\") must fail, and a protobuf round trip must still Validate",
		"types/tx_test.go:97-148 TestTxProofUnchangable / assertBadProof: 500 random byte mutations of the serialized TxProof; acceptance tolerated only if Total changed",
		"abci/types/types_test.go:13-45 TestHashAndProveResults: 6 ExecTxResults, every proof must Verify (root not hard-coded)",
		"internal/blocksync/msgs_test.go:79-140 TestBlocksyncMessageVectors: the golden BlockResponse encoding at line 103 hard-codes Header.DataHash c4da88e876062aa1543400d50d0eaa0dac88096057949cfb7bca7f3a48c04bf9, the Merkle root of Txs{\"Hello World\"} (line 81), and Header.EvidenceHash = the empty root",
		"types/test_util.go:108-125 MakeBlock; types/block.go:111-121 fillHeader, 1334-1344 Data.Hash, 1414-1419 EvidenceData.Hash; types/evidence.go:457-469 EvidenceList.Hash",
		"types/part_set.go:191-221 NewPartSetFromData (parts of partSize bytes, proofs from ProofsFromByteSlices); 293-330 AddPart (index check 304-307, duplicate 309-312, Total check 314-317, Proof.Verify 319-322)",
		"types/part_set_test.go:15-17 testPartSize = 65536; 19-65 TestBasicPartSet: AddPart must accept every part of a 100-part set; 67-106 TestWrongProof: AddPart must reject a flipped aunt (75-81), a flipped part byte (83-89), Proof.Index 2 -> 1 (91-97) and Proof.Total 100 -> 99 (99-105)",
		"types/part_set_test.go:128-170 TestPart_ValidateBasic and 197-228 TestPartProtoBuf: merkle.Proof literals for ValidateBasic and protobuf checks only (not materialized, no root)",
		"types/results.go:8-43 ABCIResults, NewResults (drops non-deterministic fields), Hash, ProveResult",
		"types/results_test.go:12-54 TestABCIResults: results {a, c, d, e, f} (lines 13-18, 29), every ProveResult(i) must Verify (lines 46-53)",
		"state/store.go:629-631 TxResultsHash; state/store_test.go:232-248 TestTxResultsHash: [{Code 32, Data \"Hello\", Log \"Huh?\"}] (lines 233-235), ProveResult(0) must Verify (line 247)",
	}
	if len(b.fx.Deviations) == 0 {
		b.fx.Deviations = []string{}
	}
	var st []string
	for _, k := range []string{
		"mutations",
		"mutation equal to input (skipped upstream too)",
		"protobuf unmarshal error",
		"rejected by ProofFromProto/ValidateBasic",
		"RootHash field changed (Validate rejects before Merkle verification)",
		"Data and LeafHash no longer consistent (Proof.Verify leaf check rejects)",
		"decoded to the original proof",
		"duplicate of an earlier representable mutation",
		"representable at the leaf-hash level",
		"representable and accepted by Validate",
	} {
		st = append(st, fmt.Sprintf("%s: %d", k, b.txStats[k]))
	}
	b.fx.Notes = strings.Join([]string{
		"RFC 9162 section 2.1 conformance: confirmed. Leaf hash SHA-256(0x00 || d), node hash SHA-256(0x01 || l || r), empty tree SHA-256(\"\"), split at the largest power of two strictly less than n (getSplitPoint matches the RFC k for every n in 2..4096 and the upstream table), no padding and no duplicated odd node. The iterative variant HashFromByteSlicesIterative promotes an odd last node unchanged, which yields the same roots; it is checked against every tree whose leaf data the program holds. Proof.Aunts is bottom to top (leaf's sibling first, root's child last). It equals RFC 9162 PATH(m, D[n]) for every proof the build step checks: all proofs of the generated sets from ProofsFromByteSlices, Txs.Proof, ABCIResults.ProveResult and the PartSet parts. In file mode, every valid inclusion case tied to a tree in the file is also re-derived by the RFC reference's PATH.",
		"Verifier: Proof.Verify(rootHash, leaf) takes leaf DATA, recomputes SHA-256(0x00 || leaf) and requires it to equal Proof.LeafHash, then runs computeHashFromAunts, which enforces 0 <= index < total, total > 0 and an exact path length (too long fails with 'unexpected inner hashes', too short with 'expected at least one inner hash'). It also rejects a nil root and negative Total/Index. On every case in this file its answer equals the RFC 9162 section 2.1.3.2 algorithm. Like the RFC algorithm it does not authenticate tree_size: a proof verifies under any claimed size with the same path shape. The strictness probe shows it, types/tx_test.go:140-144 acknowledges it in an XXX comment, and TestWrongProof 'bad proof total' is an upstream-grounded instance (see discrepancies). Hash lengths are not checked by Verify; ValidateBasic (called by ProofFromProto) requires a 32-byte LeafHash and 32-byte aunts and at most 100 aunts, which RFC 9162 does not require.",
		"Leaf-hash level: 'valid' is the implementation's verifier with the leaf-data step removed (Proof.Verify's own checks plus the unexported computeHashFromAunts, reached via go:linkname). Every inclusion case whose leaf data the program holds is also run through the exported Proof.Verify, and where the upstream test makes a different call (Verify with a mutated item and the original LeafHash, TxProof.Validate, ProofOperators.Verify, ABCIResults.ProveResult(i).Verify, PartSet.AddPart in TestBasicPartSet) that exact call is also run; all agree. TestWrongProof is the exception by design: its upstream call, AddPart, also checks Proof.Total against the PartSet header, so the program asserts separately that AddPart rejects all four parts (upstream's assertion holds) and that Proof.Verify on each proof exactly as passed to AddPart gives the leaf-hash-level answer. The node hash check uses the unexported innerHash, also via go:linkname; trees without leaf data are re-checked in file mode by the same recursion as hashFromByteSlices (tree.go:15-27) over their leaf hashes, using the implementation's emptyHash, getSplitPoint and innerHash.",
		"Published versus generated: names beginning 'published:' carry a value hard-coded upstream: the 3 TestRFC6962Hasher hash checks, the 6 TestHashFromByteSlices roots, the 14-leaf TestHeaderHash root, the 4 consensus_breakage_test.go Merkle roots, and the Header.DataHash root inside the TestBlocksyncMessageVectors golden encoding (internal/blocksync/msgs_test.go:103), plus empty_root. For that last one the program rebuilds the message exactly as msgs_test.go:81-85 does, requires the encoding to equal the literal byte for byte, decodes the literal with the implementation's own protobuf types (github.com/cometbft/cometbft/api v1.0.0), and checks its DataHash against Txs.Hash(), Data.Hash() and every tree code path, and its EvidenceHash against the empty root. No upstream test hard-codes an inclusion proof: the proof-level tests assert only that proofs verify or fail. Every inclusion case is therefore named 'generated:' and was produced by the implementation's prover (ProofsFromByteSlices, Txs.Proof, ABCIResults.ProveResult or NewPartSetFromData) over upstream leaf data or a deterministic stand-in for upstream's random data, then corrupted with the upstream corruption logic where upstream corrupts. upstream_expectation is 'valid' or 'invalid' where an upstream test asserts that outcome for that construction, else 'none'. For TestProofValidateBasic cases it reflects ValidateBasic's asserted error, while 'valid' is Verify's answer.",
		"rfc9162_valid: present only on the one case listed under discrepancies (TestWrongProof 'bad proof total'), set from the RFC 9162 section 2.1.3.2 reference in rfc9162.go. There it equals valid (true). The verifier and the reference agree on every case in the file, so no case needs an RFC answer different from valid.",
		"Leaf data: the types/* trees use leaf data produced by running upstream encoders (cdcEncode, gogoproto StdTimeMarshal, Validator.Bytes, CommitSig.ToProto().Marshal, Evidence.Bytes, Tx.Hash, MarshalTxResults, ExecTxResult.Marshal, NewResults) on verbatim copies of the upstream test literals; the program re-checks each typed Hash() (Header, ValidatorSet, Commit, Data, EvidenceList, ABCIResults, TxResultsHash) against the tree root as well as HashFromByteSlices over the written leaf data. Leaf data is not always 32 bytes (the header, validator, commit, evidence, results and tree_test.go leaves are short protobuf or literal byte strings; TestABCIResults leaf 0 is the empty string), so compare at the leaf-hash level. The Txs trees (TestDataHash, TestBlocksyncMessageVectors, TestValidTxProof, the items trees) have 32-byte leaf data (SHA-256 of the tx). The two part-set trees (TestBasicPartSet, TestWrongProof) have leaf_data null: each leaf is a 64 KiB part, so the file carries the implementation's leaf hashes (Proof.LeafHash = SHA-256(0x00 || part)), and their inclusion cases carry leaf hashes only. No tree exceeds 1,000 leaves, so no tree uses leaf_data_rule. The RFC6962 Node check has 4-byte children (\"N123\", \"N456\").",
		"Randomness: upstream's crypto-seeded cmtrand is replaced by a deterministic stream (detRand in upstream.go): block k = SHA-256(label || uint64be(k)) for k = 0, 1, 2, ...; Int() is the next block's first 8 bytes as a big-endian uint64 shifted right by 1; Bytes(n) takes ceil(n/32) fresh blocks and keeps the first n bytes. Labels: \"cometbft crypto/merkle tree_test.go TestProof\" (TestProof's extra aunt and MutateByteSlice draws), \"cometbft types/tx_test.go TestTxProofUnchangable case line L proof i\", \"cometbft strictness probe extra aunt\", \"cometbft types/tx_test.go TestValidTxProof makeTxs line 57\" (and 58, 59; makeTxs calls Bytes(size) once per tx, so tx i is the first size bytes of its own ceil(size/32) blocks), and \"cometbft types/part_set_test.go TestBasicPartSet\" and \"cometbft types/part_set_test.go TestWrongProof\" (one Bytes(6553600) call each, so part i is bytes [65536 i, 65536 (i + 1)) of the concatenation of blocks 0..204799). TestProof items are item i = SHA-256(\"item-\" + decimal i) (also types.Tx(\"item-i\").Hash(), so Txs.Hash and Txs.Proof are checked too), a stand-in for cmtrand.Bytes(32). The random-size trees of TestTxProofUnchangable (makeTxs(randInt(2, 100), randInt(16, 128)), tx_test.go:107) are not mirrored; its mutations run over the TestValidTxProof literal proofs (see below).",
		"Part sets: TestBasicPartSet (part_set_test.go:19-65) and TestWrongProof (67-106) run verbatim against the implementation (upstream_extra.go), with every testify assertion recorded as a build check. TestBasicPartSet writes 100 valid cases, one per part, each accepted by AddPart; its Part{Index: 10000} call (lines 46-48, rejected by AddPart's index check before any Merkle work) and its duplicate re-add (lines 50-52, (false, nil)) involve no proof verification and are not written. TestWrongProof writes its four parts exactly as they were passed to AddPart: 'bad trail' (part 0, Aunts[0][0] + 1), 'bad bytes' (part 1, Bytes[0] + 1; leaf_hash is SHA-256(0x00 || mutated part)), 'bad proof index' (part 2 with Proof.Index 1) and 'bad proof total' (part 3 with Proof.Total 99). The first three are invalid, as upstream asserts. The fourth is valid under Proof.Verify and under RFC 9162 section 2.1.3.2; AddPart rejects it only through its separate Total check (see discrepancies). One upstream subtlety, checked by the program: FlattenAunts and ProofsFromByteSlices hand out the same slice for a leaf trail node's hash, so flipping part 0's Aunts[0][0] also flips byte 0 of part 1's Proof.LeafHash. By the time 'bad bytes' runs, part 1's LeafHash is already corrupt, and AddPart's leaf comparison fails for both reasons. The fixture case isolates the byte flip: leaf hash of the mutated part, original path.",
		"Other callers not materialized: TestVoteProtobuf (crypto/merkle/proof_test.go:181-208), types/part_set_test.go TestPart_ValidateBasic (128-170) and TestPartProtoBuf (197-228), and internal/consensus msgs_test.go and wal_test.go hold merkle.Proof literals used only for ValidateBasic, protobuf or size checks (random LeafHash, no root). internal/consensus/replay_test.go:1055, node/node_test.go:379, store/store_test.go:184 and rpc/client/rpc_test.go:494, 576 call AddPart or Proof.Verify over blocks built at run time by a node, store or RPC fixture, with no fixed data.",
		"Odd cases: 'Too many Aunts' has a path of 101 empty strings (nil aunts); 'Invalid LeafHash' has a 10-byte zero leaf hash; 'Negative Total' and 'Negative Index' carry -1; TestVsa2022_100 has tree_size 0 and root \"\" (nil upstream); 'Mutating the rootHash' roots may be 31 bytes (MutateByteSlice can delete a byte); root \"666f6f626172\" is the ASCII string \"foobar\" from tx_test.go:75. A harness should treat any exception from such inputs as invalid.",
		"TestTxProofUnchangable materialization (3000 draws over the 6 literal TestValidTxProof proofs, 500 each as upstream): " + strings.Join(st, "; ") + ". Only decoded mutations whose RootHash is still the good root and whose LeafHash still matches SHA-256(0x00 || SHA-256(Data)) are written, because only for those is TxProof.Validate's answer the same question as leaf-hash-level verification. upstream_expectation is 'invalid' when Total is unchanged and 'none' when Total changed (tx_test.go:140-144 tolerates acceptance when Total differs, which RFC 9162 verification also allows when the path shape is unchanged). No written mutation was accepted; the strictness probe 'presented with tree_size 3' and TestWrongProof 'bad proof total' show that acceptance.",
		"Documentation drift, not a code deviation: crypto/merkle/doc.go says the tree 'tries to keep both sides of the tree the same size, but the left may be one greater' and warns that it 'does not prevent second pre-image attacks'; the code uses the RFC power-of-two split (for n = 5 the sides are 4 and 1) and domain-separated leaf and node prefixes.",
		"Provenance and re-running: this file is vectors/interop/cometbft-crypto-merkle.json in the truestamp_merkle repository, and the program that writes and confirms it is interop/go/cometbft-crypto-merkle/, a standalone Go module that requires github.com/cometbft/cometbft v1.0.1 (with github.com/cometbft/cometbft/api v1.0.0 and github.com/cosmos/gogoproto v1.7.0 for the protobuf types and their encoding). From the program directory, 'go run . -fixtures ../../../vectors/interop/cometbft-crypto-merkle.json -write' regenerates this file and then confirms it, and 'go run . -fixtures ../../../vectors/interop/cometbft-crypto-merkle.json' confirms it: the file must equal the regenerated fixture byte for byte, and every value is re-checked against the implementation and the RFC 9162 reference. Adding '-ours ../../../vectors/merkle.json' also checks the library's own vectors with this implementation.",
	}, "\n")
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

func encode(fx *Fixture) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fx); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// File-driven confirmation
// ---------------------------------------------------------------------------

type confirmResult struct {
	checks, exportedVerify, pathFromProver, pathFromReference int
	fails                                                     []string
}

func (c *confirmResult) fail(format string, args ...any) {
	c.fails = append(c.fails, fmt.Sprintf(format, args...))
}

func (c *confirmResult) ok(cond bool, format string, args ...any) {
	c.checks++
	if !cond {
		c.fail(format, args...)
	}
}

// maxRuleLeaves bounds a leaf_data_rule tree (none in this fixture uses one).
const maxRuleLeaves = 1 << 20

// ruleLeafData expands a leaf_data_rule (see LeafDataRule).
func ruleLeafData(r *LeafDataRule, n int64) ([][]byte, error) {
	if n < 0 || n > maxRuleLeaves {
		return nil, fmt.Errorf("leaf_data_rule tree_size %d outside 0..%d", n, maxRuleLeaves)
	}
	out := make([][]byte, n)
	for j := int64(0); j < n; j++ {
		i := r.First + j
		switch r.Encoding {
		case "u16le":
			out[j] = []byte{byte(i), byte(i >> 8)}
		case "u64be":
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(i))
			out[j] = b[:]
		case "decimal_ascii":
			out[j] = []byte(strconv.FormatInt(i, 10))
		default:
			return nil, fmt.Errorf("unknown leaf_data_rule encoding %q", r.Encoding)
		}
	}
	return out, nil
}

// hexField decodes a hex value read from the fixture file, recording a failure
// (never panicking) when it is not hex. An empty string decodes to an empty,
// non-nil slice, as hex.DecodeString gives.
func (c *confirmResult) hexField(what, s string) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil {
		c.fail("%s: not hex (%v)", what, err)
		return nil, false
	}
	return b, true
}

// hexFields decodes a list of hex values; ok is false if any is not hex.
func (c *confirmResult) hexFields(what string, ss []string) ([][]byte, bool) {
	out := make([][]byte, len(ss))
	good := true
	for i, s := range ss {
		b, ok := c.hexField(fmt.Sprintf("%s[%d]", what, i), s)
		out[i] = b
		good = good && ok
	}
	return out, good
}

func confirmFile(fx *Fixture) *confirmResult {
	c := &confirmResult{}
	c.ok(fx.Implementation == modulePath && fx.Version == modVersion && fx.License == modLicense, "implementation/version/license header")

	if fx.EmptyRoot != nil {
		if er, ok := c.hexField("empty_root", *fx.EmptyRoot); ok {
			c.ok(bytes.Equal(merkle.HashFromByteSlices(nil), er), "empty_root vs HashFromByteSlices(nil)")
			c.ok(bytes.Equal(merkle.HashFromByteSlices([][]byte{}), er), "empty_root vs HashFromByteSlices([])")
			c.ok(bytes.Equal(cmtEmptyHash(), er), "empty_root vs emptyHash()")
			c.ok(bytes.Equal(rfcEmptyRoot(), er), "empty_root vs RFC 9162")
		}
	}

	for _, h := range fx.HashChecks {
		want, ok := c.hexField(h.Name+": hash", h.Hash)
		if !ok {
			continue
		}
		switch h.Kind {
		case "leaf":
			if h.InputHex == nil {
				c.fail("%s: leaf hash check without input_hex", h.Name)
				continue
			}
			in, ok := c.hexField(h.Name+": input_hex", *h.InputHex)
			if !ok {
				continue
			}
			c.ok(bytes.Equal(merkle.HashFromByteSlices([][]byte{in}), want), "%s: HashFromByteSlices single leaf", h.Name)
			_, ps := merkle.ProofsFromByteSlices([][]byte{in})
			c.ok(bytes.Equal(ps[0].LeafHash, want), "%s: ProofsFromByteSlices LeafHash", h.Name)
			c.ok(bytes.Equal(cmtLeafHash(in), want), "%s: leafHash", h.Name)
			c.ok(bytes.Equal(rfcLeafHash(in), want), "%s: RFC 9162 leaf hash", h.Name)
		case "node":
			if h.Left == nil || h.Right == nil {
				c.fail("%s: node hash check without left and right", h.Name)
				continue
			}
			l, ok1 := c.hexField(h.Name+": left", *h.Left)
			r, ok2 := c.hexField(h.Name+": right", *h.Right)
			if !ok1 || !ok2 {
				continue
			}
			c.ok(bytes.Equal(cmtInnerHash(l, r), want), "%s: innerHash", h.Name)
			c.ok(bytes.Equal(rfcNodeHash(l, r), want), "%s: RFC 9162 node hash", h.Name)
		default:
			c.fail("%s: unknown kind %q", h.Name, h.Kind)
		}
	}

	type treeData struct {
		data [][]byte // nil when the file carries leaf hashes only
		lh   [][]byte
	}
	byRoot := map[string][]treeData{}
	byLeafHash := map[string][]byte{}
	for _, t := range fx.Trees {
		root, ok := c.hexField(t.Name+": root", t.Root)
		if !ok {
			continue
		}
		var data, lh [][]byte
		switch {
		case t.LeafData != nil:
			c.ok(t.LeafDataRule == nil, "%s: both leaf_data and leaf_data_rule", t.Name)
			d, ok := c.hexFields(t.Name+": leaf_data", t.LeafData)
			if !ok {
				continue
			}
			data = d
		case t.LeafDataRule != nil:
			d, err := ruleLeafData(t.LeafDataRule, t.TreeSize)
			if err != nil {
				c.fail("%s: %v", t.Name, err)
				continue
			}
			data = d
		}
		if data != nil {
			c.ok(int64(len(data)) == t.TreeSize, "%s: tree_size vs leaf data", t.Name)
			lh = make([][]byte, len(data))
			for i := range data {
				lh[i] = cmtLeafHash(data[i])
				c.ok(bytes.Equal(merkle.HashFromByteSlices([][]byte{data[i]}), lh[i]), "%s: leaf %d via HashFromByteSlices", t.Name, i)
				byLeafHash[hx(lh[i])] = data[i]
			}
			if t.LeafHashes != nil {
				c.ok(len(t.LeafHashes) == len(lh), "%s: leaf_hashes length", t.Name)
				for i := range t.LeafHashes {
					if i < len(lh) {
						c.ok(t.LeafHashes[i] == hx(lh[i]), "%s: leaf %d hash", t.Name, i)
					}
				}
			}
			c.ok(bytes.Equal(merkle.HashFromByteSlices(data), root), "%s: HashFromByteSlices root", t.Name)
			c.ok(bytes.Equal(merkle.HashFromByteSlicesIterative(data), root), "%s: HashFromByteSlicesIterative root", t.Name)
			pr, _ := merkle.ProofsFromByteSlices(data)
			c.ok(bytes.Equal(pr, root), "%s: ProofsFromByteSlices root", t.Name)
		} else {
			c.ok(t.LeafHashes != nil && int64(len(t.LeafHashes)) == t.TreeSize, "%s: tree_size vs leaf_hashes", t.Name)
			l, ok := c.hexFields(t.Name+": leaf_hashes", t.LeafHashes)
			if !ok {
				continue
			}
			lh = l
		}
		c.ok(bytes.Equal(implRootFromLeafHashes(lh), root), "%s: root from leaf hashes via getSplitPoint/innerHash", t.Name)
		c.ok(bytes.Equal(rfcMTHFromLeafHashes(lh), root), "%s: RFC 9162 MTH", t.Name)
		byRoot[t.Root] = append(byRoot[t.Root], treeData{data, lh})
	}

	for _, in := range fx.Inclusion {
		lh, ok1 := c.hexField(in.Name+": leaf_hash", in.LeafHash)
		root, ok2 := c.hexField(in.Name+": root", in.Root)
		path, ok3 := c.hexFields(in.Name+": path", in.Path)
		if !ok1 || !ok2 || !ok3 {
			continue
		}
		c.ok(in.UpstreamExpectation == "valid" || in.UpstreamExpectation == "invalid" || in.UpstreamExpectation == "none", "%s: upstream_expectation %q", in.Name, in.UpstreamExpectation)
		v, _ := implVerifyLeafHash(lh, in.LeafIndex, in.TreeSize, path, root)
		c.ok(v == in.Valid, "%s: implementation verifier says %v, fixture says %v", in.Name, v, in.Valid)
		rfcWant := in.Valid
		if in.RFC9162Valid != nil {
			rfcWant = *in.RFC9162Valid
		}
		c.ok(rfcVerify(in.LeafIndex, in.TreeSize, lh, path, root) == rfcWant, "%s: RFC 9162 verifier disagrees with the fixture's RFC answer %v", in.Name, rfcWant)
		if d, ok := byLeafHash[in.LeafHash]; ok {
			p := merkle.Proof{Total: in.TreeSize, Index: in.LeafIndex, LeafHash: lh, Aunts: path}
			c.ok((p.Verify(root, d) == nil) == in.Valid, "%s: exported Proof.Verify disagrees with fixture", in.Name)
			c.exportedVerify++
		}
		if in.Valid {
			for _, td := range byRoot[in.Root] {
				if int64(len(td.lh)) == in.TreeSize && in.LeafIndex >= 0 && in.LeafIndex < in.TreeSize && bytes.Equal(td.lh[in.LeafIndex], lh) {
					if td.data != nil {
						_, ps := merkle.ProofsFromByteSlices(td.data)
						c.ok(equalAunts(ps[in.LeafIndex].Aunts, path), "%s: path differs from ProofsFromByteSlices", in.Name)
						c.pathFromProver++
					}
					c.ok(equalAunts(rfcPath(int(in.LeafIndex), td.lh), path), "%s: path differs from RFC 9162 PATH over the tree's leaf hashes", in.Name)
					c.pathFromReference++
					break
				}
			}
		}
	}
	return c
}

func main() {
	os.Exit(run(os.Args[1:]))
}

// maxFailLines caps the FAIL lines printed per phase.
const maxFailLines = 200

const usageText = `usage: go run . -fixtures <path> [-ours <path>] [-write]

  -fixtures <path>  the fixture file to confirm (required)
  -ours <path>      also check the truestamp_merkle vectors (vectors/merkle.json)
  -write            regenerate the fixture file, then confirm it
`

// oneLine keeps a FAIL message on a single line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// usageFail prints the one line a bad command line gets and returns status 1.
func usageFail(format string, args ...any) int {
	fmt.Println("FAIL usage: " + oneLine(fmt.Sprintf(format, args...)))
	return 1
}

// run is the whole program; it returns the exit status.
func run(args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			code = usageFail("internal error while reading the arguments: %v", r)
		}
	}()

	fs := flag.NewFlagSet("cometbft-crypto-merkle", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors become one FAIL line; -h prints usageText
	write := fs.Bool("write", false, "")
	path := fs.String("fixtures", "", "")
	ours := fs.String("ours", "", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stderr, usageText)
			return 0
		}
		return usageFail("%v", err)
	}
	if fs.NArg() > 0 {
		return usageFail("unexpected argument %q", fs.Arg(0))
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if !given["fixtures"] {
		return usageFail("-fixtures <path> is required")
	}
	if *path == "" {
		return usageFail("-fixtures needs a non-empty path")
	}
	if given["ours"] && *ours == "" {
		return usageFail("-ours needs a non-empty path")
	}

	status := 0
	if !runPhase("fixtures", func() (string, []string) { return checkFixtures(*path, *write) }) {
		status = 1
	}
	if given["ours"] && !runPhase("ours", func() (string, []string) { return checkOurs(*ours) }) {
		status = 1
	}
	return status
}

// runPhase runs one phase, printing its OK line or one "FAIL <phase> " line per
// problem. A panic inside the phase becomes one FAIL line. It reports success.
func runPhase(phase string, check func() (string, []string)) (ok bool) {
	prefix := "FAIL " + phase + " "
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(prefix + oneLine(fmt.Sprintf("internal error: %v", r)))
			ok = false
		}
	}()
	counts, fails := check()
	if len(fails) == 0 {
		fmt.Printf("OK %s %s@%s: %s\n", phase, modulePath, modVersion, counts)
		return true
	}
	for i, f := range fails {
		if i == maxFailLines {
			fmt.Printf("%s... and %d more\n", prefix, len(fails)-maxFailLines)
			break
		}
		fmt.Println(prefix + oneLine(f))
	}
	return false
}

// checkFixtures regenerates the fixture (writing it first with -write) and
// confirms the file at path. It returns the counts for the OK line, or the
// failures.
func checkFixtures(path string, write bool) (string, []string) {
	b := build()
	b.finish()
	regenerated := encode(&b.fx)

	if write {
		if len(b.fails) > 0 {
			return "", append(b.fails, fmt.Sprintf("%d build checks failed; %s not written", len(b.fails), path))
		}
		if err := os.WriteFile(path, regenerated, 0o644); err != nil {
			return "", []string{"write: " + err.Error()}
		}
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		return "", append(b.fails, "read: "+err.Error())
	}
	var fails []string
	fails = append(fails, b.fails...)
	if !bytes.Equal(onDisk, regenerated) {
		at := 0
		for at < len(onDisk) && at < len(regenerated) && onDisk[at] == regenerated[at] {
			at++
		}
		fails = append(fails, fmt.Sprintf("%s differs from the regenerated fixture, first at line %d", path, bytes.Count(onDisk[:at], []byte("\n"))+1))
	}
	if len(onDisk) > maxFixtureBytes {
		fails = append(fails, fmt.Sprintf("%s is %d bytes, over the %d-byte budget", path, len(onDisk), maxFixtureBytes))
	}
	var fx Fixture
	if err := json.Unmarshal(onDisk, &fx); err != nil {
		return "", append(fails, "parse: "+err.Error())
	}
	c := confirmFile(&fx)
	fails = append(fails, c.fails...)

	nValid, nInvalid, nPub, nGen, nOverride := 0, 0, 0, 0, 0
	for _, in := range fx.Inclusion {
		if in.Valid {
			nValid++
		} else {
			nInvalid++
		}
		if in.RFC9162Valid != nil {
			nOverride++
		}
	}
	count := func(name string) {
		switch {
		case strings.HasPrefix(name, "published:"):
			nPub++
		case strings.HasPrefix(name, "generated:"):
			nGen++
		default:
			fails = append(fails, "unprefixed case name: "+name)
		}
	}
	for _, h := range fx.HashChecks {
		count(h.Name)
	}
	for _, t := range fx.Trees {
		count(t.Name)
	}
	for _, in := range fx.Inclusion {
		count(in.Name)
	}

	if len(fails) > 0 {
		return "", fails
	}
	rfcNote := "RFC 9162 reference agrees with the verifier on every case"
	if b.rfcDisagree > 0 {
		rfcNote = fmt.Sprintf("RFC 9162 reference disagrees with the verifier on %d cases", b.rfcDisagree)
	}
	return fmt.Sprintf("%d hash checks, %d trees, %d inclusion (%d valid, %d invalid; %d also via exported Proof.Verify, %d valid paths re-derived by the prover and %d by the RFC reference), %d published + %d generated cases, %d discrepancies, %d rfc9162_valid overrides; %s; %d build checks + %d file checks; %d bytes",
		len(fx.HashChecks), len(fx.Trees), len(fx.Inclusion), nValid, nInvalid,
		c.exportedVerify, c.pathFromProver, c.pathFromReference, nPub, nGen, len(fx.Discrepancies), nOverride, rfcNote, b.checks, c.checks, len(onDisk)), nil
}
