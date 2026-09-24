// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains test logic transcribed from
// github.com/google/certificate-transparency@v0.0.0-20230802103341-0fe5116f4289
// (Apache-2.0): python/ct/crypto/merkle_test.py:398-497 (the rightmost-node
// proofs and proofs_per_tree_size), at the line ranges named below. The
// upstream license is vendored as LICENSE-certificate-transparency; see NOTICE.

package main

// build assembles the fixture file from the verbatim upstream literals in
// upstream_tdm.go and upstream_lineage.go. Values that upstream derives
// (leaf hashes of upstream leaf data, and the few node hashes the Python CT
// tests build by formula) are computed here with indepHasher, a direct
// crypto/sha256 implementation of the RFC 9162 prefixes, so that no fixture
// value comes from the implementation under test except:
//   - the "valid" flag of every inclusion case, which the task defines as the
//     implementation's verifier verdict, and
//   - the "generated:" cases, which are the implementation's own output by
//     design.
// check.go then confirms every value with the implementation's functions.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

type HashCheck struct {
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	InputHex *string `json:"input_hex,omitempty"`
	Left     *string `json:"left,omitempty"`
	Right    *string `json:"right,omitempty"`
	Hash     string  `json:"hash"`
}

// Tree lists either leaf_hashes (with leaf_data when upstream gives the
// data), or, for the compact/range_test.go golden trees, a leaf_data_rule with
// leaf_data and leaf_hashes null.
type Tree struct {
	Name         string        `json:"name"`
	LeafData     []string      `json:"leaf_data"`
	LeafHashes   []string      `json:"leaf_hashes"`
	LeafDataRule *LeafDataRule `json:"leaf_data_rule"`
	TreeSize     uint64        `json:"tree_size"`
	Root         string        `json:"root"`
}

type Inclusion struct {
	Name      string   `json:"name"`
	LeafHash  string   `json:"leaf_hash"`
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	Path      []string `json:"path"`
	Root      string   `json:"root"`
	Valid     bool     `json:"valid"`
	// RFC9162Valid is present only when the implementation's verdict differs
	// from RFC 9162 section 2.1.3.2 (rfc9162Verify, typed); it is the RFC
	// answer. No case in this file needs it.
	RFC9162Valid        *bool  `json:"rfc9162_valid,omitempty"`
	UpstreamExpectation string `json:"upstream_expectation"`
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

// indepHasher is RFC 9162 section 2.1 hashing written directly on
// crypto/sha256. It satisfies merkle.LogHasher so the verbatim upstream
// reference functions (refRootHash) can run on it.
type indepHasher struct{}

func (indepHasher) EmptyRoot() []byte {
	h := sha256.Sum256(nil)
	return h[:]
}

func (indepHasher) HashLeaf(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(b)
	return h.Sum(nil)
}

func (indepHasher) HashChildren(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func (indepHasher) Size() int { return sha256.Size }

var ih = indepHasher{}

func x(b []byte) string { return hex.EncodeToString(b) }

func xs(bs [][]byte) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		out = append(out, x(b))
	}
	return out
}

func sp(s string) *string { return &s }

func nonNil(p [][]byte) [][]byte {
	if p == nil {
		return [][]byte{}
	}
	return p
}

func b64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

const (
	pVerify    = "published: proof/verify_test.go"
	pProof     = "published: proof/proof_test.go"
	pRef       = "published: testonly/reference_test.go"
	pConst     = "published: testonly/constants.go"
	pRFC       = "published: rfc6962/rfc6962_test.go"
	pGolden    = "published: compact/range_test.go TestGetRootHashGolden"
	pTrillian  = "trillian: merkle/log_verifier_test.go@v1.0.1"
	pCtCpp     = "ct-cpp: cpp/merkletree"
	pCtPy      = "ct-python: python/ct/crypto/merkle_test.py"
	pGenerated = "generated: testonly/tree_test.go genEntries (strconv.Itoa)"
	pVectors   = "published: main@fbbcd741c3d1 testonly/vectors_test.go"
)

var sources = []string{
	"github.com/transparency-dev/merkle@v0.0.2 testonly/constants.go:21-33 LeafInputs (8 leaf inputs)",
	"github.com/transparency-dev/merkle@v0.0.2 testonly/constants.go:39-60 NodeHashes (every complete subtree hash of the 8-leaf tree)",
	"github.com/transparency-dev/merkle@v0.0.2 testonly/constants.go:65-77 RootHashes (roots for tree sizes 0..8)",
	"github.com/transparency-dev/merkle@v0.0.2 testonly/constants.go:99-101 EmptyRootHash",
	"github.com/transparency-dev/merkle@v0.0.2 rfc6962/rfc6962_test.go:23-70 TestRFC6962Hasher (empty root, empty leaf, leaf, node vectors)",
	"github.com/transparency-dev/merkle@v0.0.2 proof/verify_test.go:40-66,91-111 sha256SomeHash, sha256EmptyTreeHash, inclusionProofs, roots, leaves",
	"github.com/transparency-dev/merkle@v0.0.2 proof/verify_test.go:136-176 corruptInclusionProof (corruption generator, copied verbatim and run over inclusionProofs[1..5])",
	"github.com/transparency-dev/merkle@v0.0.2 proof/verify_test.go:272-297 TestVerifyInclusionSingleEntry (4 cases)",
	"github.com/transparency-dev/merkle@v0.0.2 proof/verify_test.go:299-329 TestVerifyInclusion (12 invalid probes, then verifierCheck over inclusionProofs[1..5])",
	"github.com/transparency-dev/merkle@v0.0.2 testonly/reference_test.go:123-163 TestRefInclusionProof (7 published paths; 2 not already in verify_test.go)",
	"github.com/transparency-dev/merkle@v0.0.2 compact/range_test.go:411-495 TestGetRootHashGolden (roots for 11 sizes up to 65535, plus ephemeral node hashes; leaf data at line 472, given here as leaf_data_rule u16le)",
	"github.com/transparency-dev/merkle@v0.0.2 proof/proof_test.go:47-131 TestInclusion (25 node-ID shapes: 5 index >= size errors, 20 paths of which 2 repeat; materialized as hash-level proofs over genEntries leaf data)",
	"github.com/transparency-dev/merkle@v0.0.2 testonly/tree_test.go:196-203 genEntries (leaf data of the proof_test.go TestInclusion cases and of the generated: cases)",
	"github.com/transparency-dev/merkle@v0.0.3-0.20260921095310-fbbcd741c3d1 (main, untagged) testdata/inclusion/**/*.json (98 files; upstream's own materialization of the v0.0.2 verify_test.go cases, used as a cross-check, adds no new case)",
	"github.com/google/trillian@v1.0.1 merkle/log_verifier_test.go:165-173 verifierCheck 'Modify single element of the proof' (proof[i] = sha256EmptyTreeHash; unchanged through v1.1.0)",
	"github.com/google/trillian@v1.0.1 merkle/log_verifier_test.go:299-314 TestVerifyInclusionProof 'invalid path 1-4' probes (root []byte{}, leafHash []byte{1})",
	"github.com/google/trillian@v1.4.2 merkle/ (last release shipping the merkle packages; fixtures identical to transparency-dev/merkle@v0.0.2, nothing additional; its logverifier is used as a second verifier)",
	"github.com/google/certificate-transparency@v0.0.0-20230802103341-0fe5116f4289 cpp/merkletree/tree_hasher_test.cc:31-45 sha256_leaves, sha256_nodes",
	"github.com/google/certificate-transparency@v0.0.0-20230802103341-0fe5116f4289 cpp/merkletree/merkle_tree_test.cc:662-726 VerifierCheck (wrong leaf as hashed data at 677-680; element replacement at 689-695)",
	"github.com/google/certificate-transparency@v0.0.0-20230802103341-0fe5116f4289 cpp/merkletree/merkle_tree_test.cc:809-824 MerkleVerifierTest.VerifyPath invalid-path probes",
	"github.com/google/certificate-transparency@v0.0.0-20230802103341-0fe5116f4289 python/ct/crypto/merkle_test.py:80-86 TreeHasherTest.test_hash_full_tree (5-leaf tree \"abcde\", root by the formula h(h(h(l,l),h(l,l)),l))",
	"github.com/google/certificate-transparency@v0.0.0-20230802103341-0fe5116f4289 python/ct/crypto/merkle_test.py:176-247 real CT log inclusion proof (leaf 848049 of 3630887, 22-hash audit path, raw leaf, leaf hash, root)",
	"github.com/google/certificate-transparency@v0.0.0-20230802103341-0fe5116f4289 python/ct/crypto/merkle_test.py:253-254,344-497 MerkleVerifierTest inclusion tests (good/bad/short/long proofs, rightmost-node proofs, all proofs for tree sizes 1..4)",
	"github.com/transparency-dev/merkle@v0.0.3-0.20260921095310-fbbcd741c3d1 (main, untagged) testonly/vectors_test.go:26-104 TestSubtreeHashVectors (digest " + subtreeHashVectorsWant + ") and TestSubtreeInclusionProofVectors (digest " + subtreeInclusionProofVectorsWant + "), the draft-ietf-plants-merkle-tree-certs 'Subtree Test Vectors' over 130 one-byte leaves d[i] = i; the interop program reproduces both digests over the full row sets; a deterministic subset of the start = 0 inclusion rows is listed here (see notes)",
	"github.com/transparency-dev/merkle@v0.0.3-0.20260921095310-fbbcd741c3d1 (main, untagged) testonly/tree.go:162-198 isSubtreeValid and bitCeil (the row filter of those two tests)",
}

type builder struct {
	f *Fixture
}

func (b *builder) leafCheck(name string, input []byte, hash []byte) {
	b.f.HashChecks = append(b.f.HashChecks, HashCheck{Name: name, Kind: "leaf", InputHex: sp(x(input)), Hash: x(hash)})
}

func (b *builder) nodeCheck(name string, left, right, hash []byte) {
	b.f.HashChecks = append(b.f.HashChecks, HashCheck{Name: name, Kind: "node", Left: sp(x(left)), Right: sp(x(right)), Hash: x(hash)})
}

func (b *builder) tree(name string, leafData [][]byte, leafHashes [][]byte, root []byte) {
	if len(leafData) != len(leafHashes) {
		panic(name)
	}
	b.f.Trees = append(b.f.Trees, Tree{
		Name:       name,
		LeafData:   xs(leafData),
		LeafHashes: xs(leafHashes),
		TreeSize:   uint64(len(leafHashes)),
		Root:       x(root),
	})
}

// treeRule records a tree whose leaves follow a leaf_data_rule; leaf_data and
// leaf_hashes are null.
func (b *builder) treeRule(name string, rule LeafDataRule, size uint64, root []byte) {
	b.f.Trees = append(b.f.Trees, Tree{
		Name:         name,
		LeafDataRule: &rule,
		TreeSize:     size,
		Root:         x(root),
	})
}

// incl records an inclusion case. valid is always the implementation's
// verdict, per the task definition; rfc9162_valid is set only where that
// verdict differs from RFC 9162 section 2.1.3.2.
func (b *builder) incl(name string, leafHash []byte, index, size uint64, path [][]byte, root []byte, expectation string) {
	err := proof.VerifyInclusion(rfc6962.DefaultHasher, index, size, leafHash, path, root)
	var rfcValid *bool
	if rfc := rfc9162Verify(leafHash, index, size, path, root, true); rfc != (err == nil) {
		rfcValid = &rfc
	}
	b.f.Inclusion = append(b.f.Inclusion, Inclusion{
		Name:                name,
		LeafHash:            x(leafHash),
		LeafIndex:           index,
		TreeSize:            size,
		Path:                xs(path),
		Root:                x(root),
		Valid:               err == nil,
		RFC9162Valid:        rfcValid,
		UpstreamExpectation: expectation,
	})
}

// proofTestInclusionName names the materialization of one proof_test.go
// TestInclusion row after its upstream subtest ("size:index").
func proofTestInclusionName(tc proofInclusionCase) string {
	if tc.wantErr {
		return fmt.Sprintf("%s TestInclusion/%d:%d (index %d >= size %d, rejected by proof.Inclusion): leaf hash of genEntries[%d], root of genEntries[:%d], empty path",
			pProof, tc.size, tc.index, tc.index, tc.size, tc.index, tc.size)
	}
	ids := make([]string, len(tc.want.IDs))
	for i, id := range tc.want.IDs {
		ids[i] = fmt.Sprintf("(%d,%d)", id.Level, id.Index)
	}
	eph := "none"
	if tc.want.begin < tc.want.end {
		eph = fmt.Sprintf("IDs[%d:%d]", tc.want.begin, tc.want.end)
	}
	return fmt.Sprintf("%s TestInclusion/%d:%d (index %d, size %d): upstream node IDs [%s], ephemeral rehash %s, hashed over genEntries (derived)",
		pProof, tc.size, tc.index, tc.index, tc.size, strings.Join(ids, " "), eph)
}

// proofTestInclusionTreeName names the genEntries trees added for the
// TestInclusion sizes that no generated: tree covers.
func proofTestInclusionTreeName(n uint64) string {
	return fmt.Sprintf("%s TestInclusion tree of size %d over genEntries (testonly/tree_test.go:196-203; root derived by refRootHash)", pProof, n)
}

// generatedMaxSize is the largest generated: tree (sizes 1..16 over genEntries).
const generatedMaxSize = 16

// shapePath turns one TestInclusion row's node IDs into an audit path over
// entries, independently of the implementation: each ID (level, index) is the
// perfect subtree over leaves [index << level, (index + 1) << level), hashed
// with the verbatim reference refRootHash on indepHasher, and IDs[begin:end]
// fold into the ephemeral node from lower to upper levels,
// acc = node(IDs[i], acc), as documented for proof.Nodes.Rehash.
func shapePath(s inclusionShape, entries [][]byte, size uint64) [][]byte {
	hashes := make([][]byte, len(s.IDs))
	for i, id := range s.IDs {
		begin, end := id.Index<<id.Level, (id.Index+1)<<id.Level
		if end > size {
			panic(fmt.Sprintf("node (%d,%d) covers [%d,%d) beyond size %d", id.Level, id.Index, begin, end, size))
		}
		hashes[i] = refRootHash(entries[begin:end], ih)
	}
	out := [][]byte{}
	for i := 0; i < len(hashes); i++ {
		if i == s.begin && s.begin < s.end {
			acc := hashes[i]
			for j := i + 1; j < s.end; j++ {
				acc = ih.HashChildren(hashes[j], acc)
			}
			out = append(out, acc)
			i = s.end - 1
			continue
		}
		out = append(out, hashes[i])
	}
	return out
}

// subtreeVectorRow is one start = 0 row of TestSubtreeInclusionProofVectors:
// the RFC 9162 inclusion path PATH(index, D[0:size]) over d[i] = i.
type subtreeVectorRow struct {
	index, size uint64
}

// subtreeVectorRows is the deterministic subset of the start = 0 rows of
// TestSubtreeInclusionProofVectors that the fixture lists, in upstream's row
// order (size ascending, then index ascending): for every tree size n from 1
// to 130 the indexes 0, n / 2 and n - 1 (integer division, duplicates
// dropped), and every index of the size-130 tree.
func subtreeVectorRows() []subtreeVectorRow {
	var rows []subtreeVectorRow
	for n := uint64(1); n <= subtreeVectorMax; n++ {
		for i := uint64(0); i < n; i++ {
			if n == subtreeVectorMax || i == 0 || i == n/2 || i == n-1 {
				rows = append(rows, subtreeVectorRow{i, n})
			}
		}
	}
	return rows
}

func subtreeVectorCaseName(r subtreeVectorRow) string {
	return fmt.Sprintf("%s TestSubtreeInclusionProofVectors row \"%d [0, %d)\" = RFC 9162 PATH(%d, D[0:%d]) over one-byte leaves d[i] = i (derived; the full row set reproduces the published digest)",
		pVectors, r.index, r.size, r.index, r.size)
}

var subtreeVectorTreeName = pVectors + ":34-42 subtreeVectorTree, 130 one-byte leaves d[i] = i (root = MTH(D[0:130]), the \"[0, 130)\" row of TestSubtreeHashVectors; derived)"

func build() *Fixture {
	f := &Fixture{
		Implementation: "github.com/transparency-dev/merkle",
		Version:        "v0.0.2",
		License:        "Apache-2.0",
		Sources:        sources,
		HashChecks:     []HashCheck{},
		Trees:          []Tree{},
		Inclusion:      []Inclusion{},
		Deviations:     []string{},
		Discrepancies:  []string{},
	}
	b := &builder{f: f}

	f.EmptyRoot = sp(x(EmptyRootHash()))

	// ---- hash checks -------------------------------------------------------
	for _, v := range rfc6962TestVectors {
		switch v.kind {
		case "leaf":
			b.leafCheck(fmt.Sprintf("%s TestRFC6962Hasher %q", pRFC, v.desc), v.leaf, mustHex(v.want))
		case "node":
			b.nodeCheck(fmt.Sprintf("%s TestRFC6962Hasher %q (4-byte children %q, %q)", pRFC, v.desc, v.left, v.right), v.left, v.right, mustHex(v.want))
		}
	}
	nh := NodeHashes()
	inputs := LeafInputs()
	for i, h := range nh[0] {
		b.leafCheck(fmt.Sprintf("%s NodeHashes[0][%d] = leaf hash of LeafInputs[%d]", pConst, i, i), inputs[i], h)
	}
	for l := 1; l < len(nh); l++ {
		for i, h := range nh[l] {
			b.nodeCheck(fmt.Sprintf("%s NodeHashes[%d][%d] = node(NodeHashes[%d][%d], NodeHashes[%d][%d])", pConst, l, i, l-1, 2*i, l-1, 2*i+1),
				nh[l-1][2*i], nh[l-1][2*i+1], h)
		}
	}
	dataHash, _ := singleEntryCases(ih)
	b.leafCheck(pVerify+" TestVerifyInclusionSingleEntry leaf hash of \"data\" (derived; the same value is a literal in main testdata/inclusion/single-entry)", []byte("data"), dataHash)
	for i, v := range ctCppLeaves {
		if i < 2 {
			continue // "" and "00" are NodeHashes[0][0] and [0][1].
		}
		b.leafCheck(fmt.Sprintf("%s/tree_hasher_test.cc sha256_leaves[%d] (%d-byte input)", pCtCpp, i, v.inputLength), mustHex(v.input), mustHex(v.output))
	}
	for i, v := range ctCppNodes {
		b.nodeCheck(fmt.Sprintf("%s/tree_hasher_test.cc sha256_nodes[%d]", pCtCpp, i), mustHex(v.left), mustHex(v.right), mustHex(v.output))
	}
	b.leafCheck(pCtCpp+"/merkle_tree_test.cc VerifierCheck leaf hash of data \"WrongLeaf\" (derived)", []byte(ctCppWrongLeaf), ih.HashLeaf([]byte(ctCppWrongLeaf)))
	b.leafCheck(pCtPy+" MerkleVerifierTest real CT log leaf: raw_hex_leaf -> leaf_hash", mustHex(ctPyRawHexLeaf), mustHex(ctPyLeafHash))
	b.leafCheck(pCtPy+" MerkleVerifierTest leaf hash of ones (32 bytes of 0x11, derived)", mustHex(ctPyOnes), ih.HashLeaf(mustHex(ctPyOnes)))

	// ---- trees -------------------------------------------------------------
	rh := RootHashes()
	for n := 0; n <= len(inputs); n++ {
		b.tree(fmt.Sprintf("%s RootHashes()[%d] over LeafInputs()[:%d] (leaf hashes are NodeHashes()[0])", pConst, n, n),
			inputs[:n], nh[0][:n], rh[n])
	}
	for _, tc := range getRootHashGolden {
		if tc.size == 0 {
			continue // upstream expects nil from compact.Range for size 0, not a tree hash; see notes
		}
		// The rule must describe upstream's scheme (compact/range_test.go:472)
		// for every leaf of the tree.
		rule := LeafDataRule{Encoding: "u16le", First: 0}
		for i := 0; i < tc.size; i++ {
			d, err := ruleLeafData(&rule, uint64(i))
			if err != nil || !bytes.Equal(d, goldenLeafData(i)) {
				panic(fmt.Sprintf("golden leaf %d: u16le rule %x != upstream %x (%v)", i, d, goldenLeafData(i), err))
			}
		}
		b.treeRule(fmt.Sprintf("%s size %d root", pGolden, tc.size), rule, uint64(tc.size), b64(tc.wantRoot))
		for _, n := range tc.wantNodes {
			begin := n.index << n.level
			end := uint64(tc.size)
			if begin == 0 {
				continue // covers the whole tree: equal to the root above
			}
			b.treeRule(fmt.Sprintf("%s size %d ephemeral node {level %d, index %d} = MTH(D[%d:%d])", pGolden, tc.size, n.level, n.index, begin, end),
				LeafDataRule{Encoding: "u16le", First: begin}, end-begin, b64(n.hash))
		}
	}
	pyLeaves := make([][]byte, len(ctPyAllNodesLeaves))
	pyHashes := make([][]byte, len(ctPyAllNodesLeaves))
	for i, s := range ctPyAllNodesLeaves {
		pyLeaves[i] = mustHex(s)
		pyHashes[i] = ih.HashLeaf(pyLeaves[i])
	}
	for n := 1; n <= len(pyLeaves); n++ {
		b.tree(fmt.Sprintf("%s all_nodes_all_tree_sizes_up_to_4 leaves aa bb cc dd, size %d (root derived by refRootHash)", pCtPy, n),
			pyLeaves[:n], pyHashes[:n], refRootHash(pyLeaves[:n], ih))
	}
	{ // python/ct/crypto/merkle_test.py:80-86 test_hash_full_tree
		var leaves, hashes [][]byte
		for _, c := range []byte(ctPyHashFullTreeLeaves) {
			leaves = append(leaves, []byte{c})
			hashes = append(hashes, ih.HashLeaf([]byte{c}))
		}
		root := ctPyHashFullTreeRoot(ih)
		if !bytes.Equal(root, refRootHash(leaves, ih)) {
			panic("test_hash_full_tree formula root is not the RFC 9162 MTH of abcde")
		}
		b.tree(pCtPy+":80-86 TreeHasherTest.test_hash_full_tree leaves \"abcde\" (five one-byte leaves 61..65; root derived by the test's formula h(h(h(l(), l()), h(l(), l())), l()))",
			leaves, hashes, root)
	}
	tiCases := proofTestInclusionCases()
	var tiMax uint64
	for _, tc := range tiCases {
		if tc.size > tiMax {
			tiMax = tc.size
		}
		if tc.index+1 > tiMax {
			tiMax = tc.index + 1
		}
	}
	tiEntries := genEntries(tiMax)
	tiTreeSizes := map[uint64]bool{}
	for _, tc := range tiCases {
		if tc.wantErr || tc.size <= generatedMaxSize || tiTreeSizes[tc.size] {
			continue // sizes 1..16 are the generated: trees below, with the same leaves and roots
		}
		tiTreeSizes[tc.size] = true
		hashes := make([][]byte, tc.size)
		for i := range hashes {
			hashes[i] = ih.HashLeaf(tiEntries[i])
		}
		b.tree(proofTestInclusionTreeName(tc.size), tiEntries[:tc.size], hashes, refRootHash(tiEntries[:tc.size], ih))
	}
	genAll := genEntries(generatedMaxSize)
	genTree := testonly.New(rfc6962.DefaultHasher)
	genTree.AppendData(genAll...)
	for n := uint64(1); n <= 16; n++ {
		hashes := make([][]byte, n)
		for i := uint64(0); i < n; i++ {
			hashes[i] = genTree.LeafHash(i)
		}
		b.tree(fmt.Sprintf("%s size %d", pGenerated, n), genAll[:n], hashes, genTree.HashAt(n))
	}
	svEntries := subtreeVectorEntries()
	{
		hashes := make([][]byte, len(svEntries))
		for i, e := range svEntries {
			hashes[i] = ih.HashLeaf(e)
		}
		b.tree(subtreeVectorTreeName, svEntries, hashes, refRootHash(svEntries, ih))
	}

	// ---- inclusion ---------------------------------------------------------
	published := map[[2]uint64]bool{}
	for i := 1; i < 6; i++ { // verify_test.go:320 "i = 0 is an invalid path."
		p := inclusionProofs[i]
		idx := p.leaf - 1
		published[[2]uint64{idx, p.size}] = true
		leafHash := ih.HashLeaf(leaves[p.leaf-1])
		root := roots[p.size-1]
		label := fmt.Sprintf("%s inclusionProofs[%d] {leaf %d, size %d} (index %d)", pVerify, i, p.leaf, p.size, idx)
		b.incl(label+": happy path", leafHash, idx, p.size, p.proof, root, "valid")
		for _, pr := range corruptInclusionProof(idx, p.size, p.proof, root, leafHash) {
			b.incl(label+": corruptInclusionProof "+pr.desc, pr.leafHash, pr.leafIndex, pr.treeSize, pr.proof, pr.root, "invalid")
		}
		trLabel := fmt.Sprintf("%s verifierCheck inclusionProofs[%d] {leaf %d, size %d} (index %d)", pTrillian, i, p.leaf, p.size, idx)
		for j, wrong := range trillianReplaceWithEmptyTreeHash(append([][]byte(nil), p.proof...)) {
			b.incl(fmt.Sprintf("%s: proof[%d] replaced by sha256EmptyTreeHash (also ct-cpp VerifierCheck)", trLabel, j), leafHash, idx, p.size, wrong, root, "invalid")
		}
		b.incl(fmt.Sprintf("%s/merkle_tree_test.cc VerifierCheck kSHA256Paths[%d] {leaf %d (1-based), size %d} (index %d): wrong leaf, leaf hash of data \"WrongLeaf\"", pCtCpp, i, p.leaf, p.size, idx),
			ih.HashLeaf([]byte(ctCppWrongLeaf)), idx, p.size, p.proof, root, "invalid")
	}
	for _, p := range verifyInclusionProbes {
		label := fmt.Sprintf("%s TestVerifyInclusion probe:%d:%d", pVerify, p.index, p.size)
		b.incl(label+" leafHash=sha256SomeHash root=empty bytes", sha256SomeHash, p.index, p.size, [][]byte{}, []byte{}, "invalid")
		b.incl(label+" leafHash=empty bytes root=sha256EmptyTreeHash", []byte{}, p.index, p.size, [][]byte{}, sha256EmptyTreeHash, "invalid")
		b.incl(label+" leafHash=sha256SomeHash root=sha256EmptyTreeHash", sha256SomeHash, p.index, p.size, [][]byte{}, sha256EmptyTreeHash, "invalid")
	}
	_, se := singleEntryCases(ih)
	for i, tc := range se {
		exp := "valid"
		if tc.wantErr {
			exp = "invalid"
		}
		b.incl(fmt.Sprintf("%s TestVerifyInclusionSingleEntry test:%d (leaf hash of \"data\" or empty bytes)", pVerify, i), tc.leaf, 0, 1, [][]byte{}, tc.root, exp)
	}
	for _, tc := range refInclusionProofVectors {
		if published[[2]uint64{tc.index, tc.size}] {
			continue // same index, size and path as a verify_test.go inclusionProofs entry
		}
		b.incl(fmt.Sprintf("%s TestRefInclusionProof %d:%d over LeafInputs (root is RootHashes()[%d])", pRef, tc.index, tc.size, tc.size),
			nh[0][tc.index], tc.index, tc.size, tc.want, rh[tc.size], "none")
	}
	for _, p := range trillianInvalidPathProbes {
		b.incl(fmt.Sprintf("%s TestVerifyInclusionProof %s (index %d, size %d, root empty bytes, leafHash 0x01)", pTrillian, p.desc, p.index, p.size),
			p.leaf, uint64(p.index), uint64(p.size), [][]byte{}, p.root, "invalid")
	}
	for _, p := range ctCppVerifyPathProbes {
		root, rootDesc := []byte{}, "empty string"
		if p.rootIsEmptyTree {
			root, rootDesc = sha256EmptyTreeHash, "kSHA256EmptyTreeHash"
		}
		b.incl(fmt.Sprintf("%s/merkle_tree_test.cc:%d VerifyPath invalid path (leaf %d 1-based = index %d, size %d, root %s, data \"\")", pCtCpp, p.line, p.leaf1Based, p.leaf1Based-1, p.size, rootDesc),
			nh[0][0], p.leaf1Based-1, p.size, [][]byte{}, root, "invalid")
	}

	// ct-python MerkleVerifierTest.
	auditPath := make([][]byte, len(ctPySha256AuditPath))
	for i, s := range ctPySha256AuditPath {
		auditPath[i] = mustHex(s)
	}
	pyLeafHash, pyRoot := mustHex(ctPyLeafHash), mustHex(ctPyExpectedRootHash)
	ones, zeros := mustHex(ctPyOnes), mustHex(ctPyZeros)
	b.incl(pCtPy+" test_verify_leaf_inclusion_good_proof / test_calculate_root_hash_good_proof (real CT log, leaf 848049 of 3630887)",
		pyLeafHash, ctPyLeafIndex, ctPyTreeSize, auditPath, pyRoot, "valid")
	b.incl(pCtPy+" test_verify_leaf_inclusion_single_node_in_tree (root = leaf hash, size 1)",
		pyLeafHash, 0, 1, [][]byte{}, pyLeafHash, "valid")
	b.incl(pCtPy+" test_verify_leaf_inclusion_bad_proof (root = zeros)",
		pyLeafHash, ctPyLeafIndex, ctPyTreeSize, auditPath, zeros, "invalid")
	b.incl(pCtPy+" test_calculate_root_too_short_proof (leaf_index + 2^(len(path)+1))",
		pyLeafHash, ctPyLeafIndex+(uint64(1)<<(len(auditPath)+1)), ctPyTreeSize, auditPath, pyRoot, "invalid")
	b.incl(pCtPy+" test_verify_leaf_inclusion_incorrect_length_proof too long (leaf ones, index 0, size 4, path zeros x3, root zeros)",
		ih.HashLeaf(ones), 0, 4, [][]byte{zeros, zeros, zeros}, zeros, "invalid")
	b.incl(pCtPy+" test_verify_leaf_inclusion_incorrect_length_proof too short (leaf ones, index 0, size 4, path zeros x1, root zeros)",
		ih.HashLeaf(ones), 0, 4, [][]byte{zeros}, zeros, "invalid")
	hS1 := ih.HashLeaf(ones)
	{ // lines 398-411
		hC3 := ih.HashChildren(zeros, hS1)
		hC2 := ih.HashChildren(zeros, hC3)
		hRoot := ih.HashChildren(zeros, hC2)
		b.incl(pCtPy+" test_verify_leaf_inclusion_rightmost_node_in_tree (index 7, size 8, path zeros x3; root derived)",
			hS1, 7, 8, [][]byte{zeros, zeros, zeros}, hRoot, "valid")
	}
	{ // lines 413-424
		hRoot := ih.HashChildren(zeros, hS1)
		b.incl(pCtPy+" test_verify_leaf_inclusion_rightmost_node_in_unbalanced_odd_tree (index 4, size 5, path zeros x1; root derived)",
			hS1, 4, 5, [][]byte{zeros}, hRoot, "valid")
	}
	{ // lines 426-439
		hL2 := ih.HashChildren(zeros, hS1)
		hRoot := ih.HashChildren(zeros, hL2)
		b.incl(pCtPy+" test_verify_leaf_inclusion_rightmost_node_in_unbalanced_tree_odd_node (index 5, size 6, path zeros x2; root derived)",
			hS1, 5, 6, [][]byte{zeros, zeros}, hRoot, "valid")
	}
	{ // lines 441-454
		hL2 := ih.HashChildren(hS1, zeros)
		hRoot := ih.HashChildren(zeros, hL2)
		b.incl(pCtPy+" test_verify_leaf_inclusion_rightmost_node_in_unbalanced_even_tree (index 4, size 6, path zeros x2; root derived)",
			hS1, 4, 6, [][]byte{zeros, zeros}, hRoot, "valid")
	}
	{ // lines 465-497, proofs_per_tree_size at 470-481
		lh := pyHashes
		hc := ih.HashChildren
		proofsPerTreeSize := map[int][][][]byte{
			1: {{}},
			2: {{lh[1]}, {lh[0]}},
			3: {{lh[1], lh[2]}, // leaf 0
				{lh[0], lh[2]},      // leaf 1
				{hc(lh[0], lh[1])}}, // leaf 2
			4: {{lh[1], hc(lh[2], lh[3])}, // leaf 0
				{lh[0], hc(lh[2], lh[3])}, // leaf 1
				{lh[3], hc(lh[0], lh[1])}, // leaf 2
				{lh[2], hc(lh[0], lh[1])}, // leaf 3
			},
		}
		for size := 1; size <= 4; size++ {
			root := refRootHash(pyLeaves[:size], ih)
			for j := 0; j < size; j++ {
				b.incl(fmt.Sprintf("%s test_verify_leaf_inclusion_all_nodes_all_tree_sizes_up_to_4 size %d leaf %d (path and root derived)", pCtPy, size, j),
					lh[j], uint64(j), uint64(size), proofsPerTreeSize[size][j], root, "valid")
			}
		}
	}

	// proof/proof_test.go TestInclusion: the upstream node-ID shapes as
	// hash-level proofs over genEntries. The valid rows carry
	// upstream_expectation "none" (the test asserts node IDs and never runs
	// a verifier); the wantErr rows (index >= size) carry "invalid".
	seenTI := map[string]bool{}
	for _, tc := range tiCases {
		name := proofTestInclusionName(tc)
		if seenTI[name] {
			continue // lines 92-95 repeat 7:1 and 7:3 from lines 77-82 with the same want
		}
		seenTI[name] = true
		leafHash := ih.HashLeaf(tiEntries[tc.index])
		root := refRootHash(tiEntries[:tc.size], ih)
		if tc.wantErr {
			b.incl(name, leafHash, tc.index, tc.size, [][]byte{}, root, "invalid")
			continue
		}
		path := shapePath(tc.want, tiEntries, tc.size)
		if !pathsEqual(path, refInclusionProof(tiEntries[:tc.size], tc.index, ih)) {
			panic(fmt.Sprintf("TestInclusion/%d:%d: path from the upstream node IDs differs from the reference refInclusionProof", tc.size, tc.index))
		}
		b.incl(name, leafHash, tc.index, tc.size, path, root, "none")
	}

	// generated: the implementation's own prover over genEntries.
	for n := uint64(1); n <= generatedMaxSize; n++ {
		root := genTree.HashAt(n)
		for i := uint64(0); i < n; i++ {
			path, err := genTree.InclusionProof(i, n)
			if err != nil {
				panic(err)
			}
			if path == nil {
				path = [][]byte{}
			}
			b.incl(fmt.Sprintf("%s size %d index %d (path from testonly.Tree.InclusionProof)", pGenerated, n, i),
				genTree.LeafHash(i), i, n, path, root, "none")
		}
	}

	// main testonly/vectors_test.go TestSubtreeInclusionProofVectors: the
	// start = 0 rows of subtreeVectorRows, derived with the verbatim reference
	// functions. The test compares one digest over all rows and never runs a
	// verifier, so upstream_expectation is "none".
	for _, r := range subtreeVectorRows() {
		entries := svEntries[:r.size]
		b.incl(subtreeVectorCaseName(r), ih.HashLeaf(entries[r.index]), r.index, r.size,
			nonNil(refInclusionProof(entries, r.index, ih)), refRootHash(entries, ih), "none")
	}

	for _, c := range f.Inclusion {
		if c.RFC9162Valid != nil {
			f.Discrepancies = append(f.Discrepancies, fmt.Sprintf("%s: implementation verdict valid=%v, RFC 9162 section 2.1.3.2 valid=%v", c.Name, c.Valid, *c.RFC9162Valid))
		}
		if c.UpstreamExpectation == "none" {
			continue
		}
		if (c.UpstreamExpectation == "valid") != c.Valid {
			f.Discrepancies = append(f.Discrepancies, fmt.Sprintf("%s: upstream expects %s, implementation verdict valid=%v", c.Name, c.UpstreamExpectation, c.Valid))
		}
	}

	f.Notes = strings.Join(notes, " ")
	return f
}

var notes = []string{
	"Conformance: rfc6962.Hasher uses leaf = SHA-256(0x00 || data), node = SHA-256(0x01 || left || right), empty = SHA-256(\"\");",
	"the tree shape (testonly.Tree, compact.Range, and the reference refRootHash in testonly/reference_test.go) splits at the largest power of two smaller than n with no padding or duplication;",
	"proof.Inclusion / testonly.Tree.InclusionProof return the audit path bottom to top; proof.VerifyInclusion requires index < size and the exact path length (inner + border from decompInclProof).",
	"It is stricter than the RFC 9162 section 2.1.3.2 text in one way that never changes a verdict for well-formed input: it rejects a leaf hash whose length is not 32 before hashing (cases with 0-, 1- and 9-byte leaf hashes, and 0-byte roots or path elements, exist here and are all invalid). Path elements are not length-checked; a wrong-length element simply yields a mismatched root.",
	"rfc9162_valid appears on no case: every verdict equals RFC 9162 section 2.1.3.2 applied to SHA-256 outputs (leaf hash, root and path elements of 32 bytes), which the interop program recomputes with its own transcription of the algorithm. Run on bytes of any length, the bare algorithm would accept exactly one case, 'TestVerifyInclusionSingleEntry test:3' (index 0, size 1, empty leaf hash, empty root, empty path), because r = the empty leaf hash equals the empty root; it is invalid here because an empty string is not a SHA-256 hash, and proof.VerifyInclusion rejects any leaf hash that is not 32 bytes.",
	"Input shapes the consumer must accept: leaf_hash, root and path elements are NOT always 32 bytes in the invalid cases (\"\" = empty bytes, \"01\", 9-byte \"WrongLeaf\"); leaf_index can be 18446744073709551615 (uint64 wrap of index 0 minus 1, the corruptInclusionProof 'leafIndex - 1' case) or larger than tree_size; tree_size can be 0. A verifier that raises on such input should be treated as returning invalid.",
	"The 'RFC6962 Node' hash check hashes two 4-byte children (\"N123\", \"N456\"); an API restricted to 32-byte children cannot take it directly.",
	"Published versus generated: every name starting 'published:', 'trillian:', 'ct-cpp:' or 'ct-python:' is an upstream literal or an upstream test case materialized by running the upstream logic (verbatim copies in the interop program's upstream_*.go files); values marked 'derived' are leaf or node hashes computed from upstream leaf data with the RFC prefixes, as the upstream test itself computes them.",
	"The 98 inclusion cases named 'published: proof/verify_test.go' are exactly what TestVerifyInclusion and TestVerifyInclusionSingleEntry assert (5 happy paths, 77 corruptInclusionProof probes, 12 invalid probes, 4 single-entry cases); they match, one for one, the 98 JSON files upstream later committed on main under testdata/inclusion (checked by the interop program).",
	"inclusionProofs[0] = {0, 0, nil} is skipped exactly as upstream skips it ('i = 0 is an invalid path', a 1-based leaf 0).",
	"TestRefInclusionProof publishes 7 paths; 5 are identical to inclusionProofs[1..5] and are not repeated, 2 (0:2 and 1:2) are included with upstream_expectation 'none' because that test only compares paths and never runs a verifier.",
	"compact/range_test.go TestGetRootHashGolden: 11 roots (sizes 10..65535, leaf i data = [i & 0xff, (i >> 8) & 0xff]) plus 11 ephemeral node hashes, each the RFC 9162 MTH of the leaf range D[index << level : size], included as their own trees; ephemeral nodes that cover the whole tree equal the root and are not repeated.",
	"These 22 golden trees give leaf_data_rule {\"encoding\": \"u16le\", \"first\": b} instead of listing leaves, with leaf_data and leaf_hashes null: leaf i, for i from first to first + tree_size - 1, has data = the 2 bytes [i & 0xff, (i >> 8) & 0xff] (little-endian; every i here is at most 65534, so this is exactly upstream's scheme) and leaf hash SHA-256(0x00 || data). A whole-tree entry has first = 0; the ephemeral node over D[b:size] has first = b and tree_size = size - b. Every published root is kept.",
	"Its size-0 entry expects compact.Range.GetRootHash to return nil for an empty range (upstream TODO to return EmptyRoot); that is an API quirk of compact.Range, not a tree hash, and is not included. testonly.Tree.HashAt(0) and rfc6962 EmptyRoot both return SHA-256(\"\").",
	"testonly.CompactTrees() is not included separately: every entry is a NodeHashes() value already covered by the node hash checks.",
	"proof/proof_test.go TestInclusion (lines 47-131) publishes node-ID shapes, not hashes: for 20 (size, index) rows up to size 95 it asserts which node IDs proof.Inclusion returns and which of them fold into the ephemeral node (IDs[begin:end]), and it asserts that 5 rows with index >= size are rejected. Each row is materialized here over genEntries leaf data (leaf i = the ASCII decimal digits of i, testonly/tree_test.go:196-203): node ID (level, index) is the MTH of leaves [index << level, (index + 1) << level), IDs[begin:end] fold as acc = node(IDs[i], acc) from lower to upper levels, and the resulting path must equal the verbatim reference refInclusionProof. The valid rows have upstream_expectation 'none' (the test never runs a verifier); 7:1 and 7:3 appear twice in the table (lines 77-82 and 92-95, same want) and once here.",
	"The 5 TestInclusion error rows (size:index 0:0, 0:1, 1:2, 0:3, 7:8) become invalid cases with the leaf hash of genEntries[index], the root of genEntries[:size] (SHA-256(\"\") for size 0) and an empty path, upstream_expectation 'invalid'. Rows of size up to 16 share leaves and roots with the generated: trees; sizes 31 and 95 get their own trees, with roots derived by refRootHash.",
	"Apart from those shapes, upstream derives inclusion proofs for trees larger than 8 leaves only by comparing two of its own code paths (testonly.Tree.InclusionProof against refInclusionProof over genEntries(256) in testonly/tree_test.go, and in Trillian verifierCheck over 'data:%d' trees of sizes 1..70, 1024, 5050); no literal answers exist for them. The 'generated:' cases (16 trees, 136 inclusion proofs, sizes 1..16 over genEntries) are the implementation's own output, kept only to exercise its prover on more shapes, with upstream_expectation 'none'.",
	"Lineage: trillian v1.1.1 through v1.4.2 (the last release that still ships merkle/, deprecated in favour of transparency-dev/merkle) carry the same constants, inclusion vectors, corruptInclusionProof, probes and compact goldens as transparency-dev/merkle@v0.0.2, so they add nothing.",
	"trillian v1.0.1 to v1.1.0 used an older corruption set: replacing each path element by sha256EmptyTreeHash (10 'trillian:' cases) and invalid-path probes with a 1-byte leaf hash 0x01 (4 cases); its other probes duplicate v0.0.2 ones.",
	"The C++ certificate-transparency tests (origin of LeafInputs, the 8 roots, 6 paths and 4 consistency proofs, all identical to the Go values) add: 2 tree_hasher_test.cc hash checks, 'wrong leaf' as hashed data \"WrongLeaf\" for each of the 5 published proofs (the Go tests pass the 9 raw bytes as a hash, which only hits the length check), and 4 invalid-path probes that map to 0-based indexes. The C++ VerifyPath probes with 1-based leaf 0 have no 0-based equivalent and are omitted.",
	"The Python tests in the same repository add a real CT log inclusion proof (leaf 848049 in a tree of 3630887, 22-hash path) with its raw MerkleTreeLeaf and leaf hash, its bad-root and out-of-range variants, too-long and too-short proofs, four rightmost-node proofs with synthetic siblings, and every proof for sizes 1..4 over leaves aa bb cc dd; roots and paths the Python test builds by formula are derived here with the RFC prefixes. Its negative-index probes are omitted (no unsigned equivalent). TreeHasherTest.test_hash_full_tree (lines 80-86) adds the 5-leaf tree over the one-byte leaves a, b, c, d, e, whose asserted root the test builds by the formula h(h(h(l(), l()), h(l(), l())), l()); that formula is the RFC 9162 MTH of 5 leaves (checked against refRootHash).",
	"Out of scope and not included: consistency proofs. Counts for reference: proof/verify_test.go has 5 published consistency proofs (consistencyProofs {1,1},{1,8},{6,8},{2,5},{6,7}), 13 fixed TestVerifyConsistency probes, and corruptConsistencyProof generates 19 or 20 probes for each of the 4 non-trivial proofs; testonly/reference_test.go TestRefConsistencyProof has 4; proof/proof_test.go TestConsistency has 27 node-ID cases (no hashes); main testdata/consistency has 98 JSON files; trillian v1.0.1 to v1.4.2 have the first 4 consistency proofs; the C++ and Python tests have the same 4 plus a few Python-only consistency probes.",
	"Also not included: proof/proof_test.go TestRehash (derived), compact/testdata/fuzz corpora (node ranges, no hashes), Trillian's VerifiedPrefixHashFromInclusionProof tests (a Trillian-only API), and main's unreleased testdata/subtreeinclusion and subtreeconsistency (204 and 285 files, for the VerifySubtreeInclusion API added after v0.0.2).",
	"transparency-dev/merkle main (commit fbbcd741c3d1, untagged) testonly/vectors_test.go:62-104 publishes two digests from the draft-ietf-plants-merkle-tree-certs 'Subtree Test Vectors' appendix, each a rolling SHA-256 over text rows for every valid subtree [start, end) with end <= 130 of the tree of one-byte leaves d[i] = i (validity per isSubtreeValid, testonly/tree.go:162-198): TestSubtreeHashVectors (" + subtreeHashVectorsWant + ", rows '[start, end) <hash>') and TestSubtreeInclusionProofVectors (" + subtreeInclusionProofVectorsWant + ", rows '<index> [start, end) <path...>').",
	"The interop program reproduces both digests over the full row sets, reading the subtree [start, end) as the RFC 9162 tree over the leaf range D[start:end] (hash MTH(D[start:end]), path PATH(index - start, D[start:end])), once with the implementation (testonly.Tree over each leaf range) and once with the verbatim reference functions on crypto/sha256; all four computations give the published values.",
	fmt.Sprintf("The start = 0 rows are ordinary RFC 9162 values: the hash rows are the roots of every tree size 0..130, and the inclusion rows are every audit path of every leaf of sizes 1..130 (%d rows). The file lists a deterministic subset of those inclusion rows, %d cases named", subtreeVectorMax*(subtreeVectorMax+1)/2, len(subtreeVectorRows())) + " 'published: main@fbbcd741c3d1 testonly/vectors_test.go TestSubtreeInclusionProofVectors row ...': for every size n from 1 to 130 the indexes 0, n / 2 and n - 1 (integer division, duplicates dropped), plus every index of the size-130 tree, with upstream_expectation 'none' (the test never runs a verifier); their roots cover every size 1..130, and the size-130 tree is listed with its 130 leaves.",
	"The start > 0 rows (subtrees that do not begin at leaf 0, for the VerifySubtreeInclusion API added after v0.0.2) are the draft's subtree semantics, not RFC 9162 tree roots or inclusion proofs; they are left out of the file and used only inside the two digests. Also not included from the same file: TestSubtreeConsistencyProofVectors (consistency, out of scope) and TestSubtreeCoveringVectors (proof.FindSubtrees ranges, no hashes); nor cmd/proofgen's subtree proof tables.",
	"The interop program is interop/go/transparency-dev-merkle/ in the truestamp_merkle repository, a standalone Go module, and this file is vectors/interop/transparency-dev-merkle.json there; from the program directory, 'go run . -fixtures ../../../vectors/interop/transparency-dev-merkle.json' checks the file and 'go run . -fixtures ../../../vectors/interop/transparency-dev-merkle.json -write' regenerates it, then checks it. The program checks every value against the implementation (rfc6962.DefaultHasher, testonly.Tree, compact.Range, proof.VerifyInclusion, proof.RootFromInclusionProof, testonly.Tree.InclusionProof for every valid case whose tree is in this file, and proof.Inclusion with Nodes.Rehash over compact.Range node hashes for the TestInclusion cases), checks the verbatim copies against the importable testonly constants, reruns upstream's own golden and TestInclusion assertions, cross-checks the main-branch testdata JSON (embedded in the program), runs every inclusion case through trillian@v1.4.2 merkle/logverifier as a second verifier, and compares every verdict with its own RFC 9162 section 2.1.3.2 transcription.",
}
