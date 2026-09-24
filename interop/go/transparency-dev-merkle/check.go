// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains the inclusionProbe JSON shape (mainProbe below) copied from
// github.com/transparency-dev/merkle@v0.0.3-0.20260921095310-fbbcd741c3d1
// (main, untagged; Apache-2.0, Copyright Google LLC) proof/verify_test.go:30-39,
// and the TestInclusion assertions and their failure text "accepted bad params"
// from github.com/transparency-dev/merkle@v0.0.2 proof/proof_test.go:114-129.
// The upstream license is vendored as LICENSE-transparency-dev-merkle; see
// NOTICE.

package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/google/trillian/merkle/logverifier"         // nolint:staticcheck
	trillianrfc "github.com/google/trillian/merkle/rfc6962" // nolint:staticcheck
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

type checker struct {
	errs []string

	hashChecks      int
	trees           int
	treeLeaves      int
	inclusion       int
	valid, invalid  int
	proverConfirmed int
	trillianAgreed  int
	mainMatched     int
	mainFiles       int
	literalChecks   int
	discrepancies   int
	publishedCases  int
	generatedCases  int
	publishedTrees  int
	generatedTrees  int
	ruleTrees       int
	ruleLeaves      int
	rfcAgreed       int
	bareRFCDiffers  []string
	tiRows          int
	tiCases         int
	svHashRows      int // TestSubtreeHashVectors rows folded into the digest
	svProofRows     int // TestSubtreeInclusionProofVectors rows folded into the digest
	svStart0Rows    int // of which start = 0
	svDigests       int // digest reproductions that matched (2 tests x 2 computations)
	svCases         int // start = 0 rows listed in the fixture and confirmed
}

func (c *checker) fail(format string, args ...any) {
	c.errs = append(c.errs, oneLine(fmt.Sprintf(format, args...)))
}

// oneLine keeps each problem on its own FAIL line: some errors from the
// implementation (RootMismatchError) span several lines.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func unhex(c *checker, what, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		c.fail("%s: bad hex %q: %v", what, s, err)
	}
	return b
}

func unhexList(c *checker, what string, ss []string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = unhex(c, fmt.Sprintf("%s[%d]", what, i), s)
	}
	return out
}

// selfCheckUpstream confirms that the verbatim copies equal what the
// implementation exports, and reruns upstream's own assertions over the
// copied literals using the implementation's functions.
func (c *checker) selfCheckUpstream() {
	h := rfc6962.DefaultHasher

	// The testonly constants are importable: the copies must be identical.
	if !reflect.DeepEqual(LeafInputs(), testonly.LeafInputs()) {
		c.fail("LeafInputs copy differs from testonly.LeafInputs()")
	}
	if !reflect.DeepEqual(NodeHashes(), testonly.NodeHashes()) {
		c.fail("NodeHashes copy differs from testonly.NodeHashes()")
	}
	if !reflect.DeepEqual(RootHashes(), testonly.RootHashes()) {
		c.fail("RootHashes copy differs from testonly.RootHashes()")
	}
	if !bytes.Equal(EmptyRootHash(), testonly.EmptyRootHash()) {
		c.fail("EmptyRootHash copy differs from testonly.EmptyRootHash()")
	}
	c.literalChecks += 4

	// TestRFC6962Hasher.
	for _, v := range rfc6962TestVectors {
		var got []byte
		switch v.kind {
		case "empty":
			got = h.EmptyRoot()
		case "leaf":
			got = h.HashLeaf(v.leaf)
		case "node":
			got = h.HashChildren(v.left, v.right)
		}
		if hex.EncodeToString(got) != v.want {
			c.fail("TestRFC6962Hasher %q: got %x want %s", v.desc, got, v.want)
		}
		c.literalChecks++
	}

	// verify_test.go roots/leaves agree with the constants.
	for i, r := range roots {
		if !bytes.Equal(r, RootHashes()[i+1]) {
			c.fail("verify_test roots[%d] != RootHashes()[%d]", i, i+1)
		}
	}
	if !reflect.DeepEqual(leaves, LeafInputs()) {
		c.fail("verify_test leaves != LeafInputs()")
	}

	// TestVerifyInclusion's verifierCheck over inclusionProofs[1..5]: the
	// implementation's RootFromInclusionProof, VerifyInclusion, its prover,
	// and every corruption rejected.
	tree := testonly.New(h)
	tree.AppendData(LeafInputs()...)
	for i := 1; i < 6; i++ {
		p := inclusionProofs[i]
		leafHash := h.HashLeaf(leaves[p.leaf-1])
		root := roots[p.size-1]
		got, err := proof.RootFromInclusionProof(h, p.leaf-1, p.size, leafHash, p.proof)
		if err != nil || !bytes.Equal(got, root) {
			c.fail("inclusionProofs[%d]: RootFromInclusionProof = %x, %v", i, got, err)
		}
		gotPath, err := tree.InclusionProof(p.leaf-1, p.size)
		if err != nil || !pathsEqual(gotPath, p.proof) {
			c.fail("inclusionProofs[%d]: implementation prover path %x != published %x (%v)", i, gotPath, p.proof, err)
		}
		for _, pr := range corruptInclusionProof(p.leaf-1, p.size, p.proof, root, leafHash) {
			if proof.VerifyInclusion(h, pr.leafIndex, pr.treeSize, pr.leafHash, pr.proof, pr.root) == nil {
				c.fail("inclusionProofs[%d]: corruption %q verified", i, pr.desc)
			}
		}
		c.literalChecks++
	}

	// TestRefInclusionProof: the verbatim reference AND the implementation's
	// prover must both reproduce each literal path.
	for _, tc := range refInclusionProofVectors {
		ref := refInclusionProof(LeafInputs()[:tc.size], tc.index, h)
		if !pathsEqual(ref, tc.want) {
			c.fail("TestRefInclusionProof %d:%d: refInclusionProof %x != literal", tc.index, tc.size, ref)
		}
		got, err := tree.InclusionProof(tc.index, tc.size)
		if err != nil || !pathsEqual(got, tc.want) {
			c.fail("TestRefInclusionProof %d:%d: implementation prover %x != literal (%v)", tc.index, tc.size, got, err)
		}
		c.literalChecks++
	}

	// TestGetRootHashGolden, as upstream asserts it: root and visited
	// ephemeral nodes from compact.Range.GetRootHash.
	factory := &compact.RangeFactory{Hash: h.HashChildren}
	for _, tc := range getRootHashGolden {
		rng := factory.NewEmptyRange(0)
		for i := 0; i < tc.size; i++ {
			if err := rng.Append(h.HashLeaf(goldenLeafData(i)), nil); err != nil {
				c.fail("golden %d: Append: %v", tc.size, err)
			}
		}
		visited := []goldenNode{}
		root, err := rng.GetRootHash(func(id compact.NodeID, hash []byte) {
			visited = append(visited, goldenNode{level: id.Level, index: id.Index, hash: base64.StdEncoding.EncodeToString(hash)})
		})
		if err != nil {
			c.fail("golden %d: GetRootHash: %v", tc.size, err)
		}
		if got := base64.StdEncoding.EncodeToString(root); got != tc.wantRoot {
			c.fail("golden %d: root %q want %q", tc.size, got, tc.wantRoot)
		}
		if tc.wantNodes != nil && !reflect.DeepEqual(visited, tc.wantNodes) {
			c.fail("golden %d: visited %v want %v", tc.size, visited, tc.wantNodes)
		}
		c.literalChecks++
	}

	// proof/proof_test.go TestInclusion, as upstream asserts it (lines
	// 114-129): proof.Inclusion rejects the wantErr rows and otherwise returns
	// exactly the listed IDs, begin and end (the ephemeral node ID is ignored).
	for _, tc := range proofTestInclusionCases() {
		nodes, err := proof.Inclusion(tc.index, tc.size)
		if tc.wantErr {
			if err == nil {
				c.fail("TestInclusion/%d:%d: proof.Inclusion accepted bad params", tc.size, tc.index)
			}
		} else if err != nil {
			c.fail("TestInclusion/%d:%d: proof.Inclusion: %v", tc.size, tc.index, err)
		} else {
			_, begin, end := nodes.Ephem()
			if !reflect.DeepEqual(nodes.IDs, tc.want.IDs) || begin != tc.want.begin || end != tc.want.end {
				c.fail("TestInclusion/%d:%d: proof.Inclusion IDs %v [%d:%d], want %v [%d:%d]", tc.size, tc.index, nodes.IDs, begin, end, tc.want.IDs, tc.want.begin, tc.want.end)
			}
		}
		c.tiRows++
		c.literalChecks++
	}

	// python/ct/crypto/merkle_test.py:80-86 test_hash_full_tree: the formula
	// on the implementation's hasher equals the implementation's tree root.
	{
		abcde := testonly.New(h)
		for _, ch := range []byte(ctPyHashFullTreeLeaves) {
			abcde.AppendData([]byte{ch})
		}
		if got := ctPyHashFullTreeRoot(h); !bytes.Equal(got, abcde.Hash()) {
			c.fail("ct-python test_hash_full_tree: formula %x, testonly.Tree root %x", got, abcde.Hash())
		}
		c.literalChecks++
	}

	// Lineage literals that are checkable on their own.
	for _, v := range ctCppLeaves {
		if got := hex.EncodeToString(h.HashLeaf(mustHex(v.input))); got != v.output {
			c.fail("ct-cpp leaf %q: %s want %s", v.input, got, v.output)
		}
		c.literalChecks++
	}
	for _, v := range ctCppNodes {
		if got := hex.EncodeToString(h.HashChildren(mustHex(v.left), mustHex(v.right))); got != v.output {
			c.fail("ct-cpp node: %s want %s", got, v.output)
		}
		c.literalChecks++
	}
	if got := hex.EncodeToString(h.HashLeaf(mustHex(ctPyRawHexLeaf))); got != ctPyLeafHash {
		c.fail("ct-python raw leaf hash %s want %s", got, ctPyLeafHash)
	}
	c.literalChecks++
}

func pathsEqual(a, b [][]byte) bool {
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

// checkFixture verifies every value in the loaded file with the
// implementation's functions, independently of build().
func (c *checker) checkFixture(f *Fixture) {
	h := rfc6962.DefaultHasher
	th := trillianrfc.DefaultHasher
	tv := logverifier.New(th)

	if f.EmptyRoot == nil {
		c.fail("empty_root is null")
	} else {
		er := unhex(c, "empty_root", *f.EmptyRoot)
		if !bytes.Equal(er, h.EmptyRoot()) || !bytes.Equal(er, testonly.New(h).HashAt(0)) || !bytes.Equal(er, th.EmptyRoot()) {
			c.fail("empty_root %s not reproduced", *f.EmptyRoot)
		}
	}

	names := map[string]bool{}
	dup := func(kind, name string) {
		k := kind + "\x00" + name
		if names[k] {
			c.fail("duplicate %s name %q", kind, name)
		}
		names[k] = true
	}

	for _, hc := range f.HashChecks {
		dup("hash", hc.Name)
		c.hashChecks++
		want := unhex(c, hc.Name, hc.Hash)
		var got, gotT []byte
		switch hc.Kind {
		case "leaf":
			if hc.InputHex == nil || hc.Left != nil || hc.Right != nil {
				c.fail("%s: malformed leaf check", hc.Name)
				continue
			}
			in := unhex(c, hc.Name, *hc.InputHex)
			got, gotT = h.HashLeaf(in), th.HashLeaf(in)
		case "node":
			if hc.InputHex != nil || hc.Left == nil || hc.Right == nil {
				c.fail("%s: malformed node check", hc.Name)
				continue
			}
			l, r := unhex(c, hc.Name, *hc.Left), unhex(c, hc.Name, *hc.Right)
			got, gotT = h.HashChildren(l, r), th.HashChildren(l, r)
		default:
			c.fail("%s: unknown kind %q", hc.Name, hc.Kind)
			continue
		}
		if !bytes.Equal(got, want) {
			c.fail("hash check %q: implementation %x, fixture %x", hc.Name, got, want)
		}
		if !bytes.Equal(gotT, want) {
			c.fail("hash check %q: trillian %x, fixture %x", hc.Name, gotT, want)
		}
	}

	type treeKey struct {
		size uint64
		root string
	}
	treesByKey := map[treeKey][]*testonly.Tree{}
	treeLeafHashes := map[*testonly.Tree][]string{}
	factory := &compact.RangeFactory{Hash: h.HashChildren}
	for i := range f.Trees {
		t := &f.Trees[i]
		dup("tree", t.Name)
		c.trees++
		if strings.HasPrefix(t.Name, "generated:") {
			c.generatedTrees++
		} else {
			c.publishedTrees++
		}
		var hashes [][]byte
		leafHex := t.LeafHashes
		if t.LeafDataRule != nil {
			// Leaves from the rule, hashed by the implementation.
			if t.LeafData != nil || t.LeafHashes != nil {
				c.fail("tree %q: leaf_data_rule with leaf_data or leaf_hashes not null", t.Name)
				continue
			}
			if t.TreeSize > 1<<16 {
				c.fail("tree %q: leaf_data_rule tree_size %d exceeds the %d leaves u16le can name", t.Name, t.TreeSize, 1<<16)
				continue
			}
			c.ruleTrees++
			hashes = make([][]byte, 0, t.TreeSize)
			for j := uint64(0); j < t.TreeSize; j++ {
				i := t.LeafDataRule.First + j
				d, err := ruleLeafData(t.LeafDataRule, i)
				if err != nil {
					c.fail("tree %q: leaf %d: %v", t.Name, i, err)
					break
				}
				if strings.HasPrefix(t.Name, pGolden) && !bytes.Equal(d, goldenLeafData(int(i))) {
					c.fail("tree %q: rule leaf %d = %x, compact/range_test.go:472 gives %x", t.Name, i, d, goldenLeafData(int(i)))
				}
				hashes = append(hashes, h.HashLeaf(d))
			}
			c.ruleLeaves += len(hashes)
			if uint64(len(hashes)) != t.TreeSize {
				continue
			}
			leafHex = make([]string, len(hashes))
			for j, lh := range hashes {
				leafHex[j] = hex.EncodeToString(lh)
			}
		} else {
			if t.LeafHashes == nil {
				c.fail("tree %q: neither leaf_hashes nor leaf_data_rule", t.Name)
				continue
			}
			if t.TreeSize != uint64(len(t.LeafHashes)) {
				c.fail("tree %q: tree_size %d but %d leaf hashes", t.Name, t.TreeSize, len(t.LeafHashes))
				continue
			}
			hashes = unhexList(c, t.Name, t.LeafHashes)
		}
		if t.LeafData != nil {
			if len(t.LeafData) != len(t.LeafHashes) {
				c.fail("tree %q: %d leaf_data vs %d leaf_hashes", t.Name, len(t.LeafData), len(t.LeafHashes))
				continue
			}
			for j, d := range t.LeafData {
				if !bytes.Equal(h.HashLeaf(unhex(c, t.Name, d)), hashes[j]) {
					c.fail("tree %q: leaf_hashes[%d] is not HashLeaf(leaf_data[%d])", t.Name, j, j)
				}
			}
		}
		c.treeLeaves += len(hashes)
		root := unhex(c, t.Name, t.Root)
		mt := testonly.New(h)
		mt.Append(hashes...)
		if !bytes.Equal(mt.Hash(), root) {
			c.fail("tree %q: testonly.Tree root %x, fixture %s", t.Name, mt.Hash(), t.Root)
		}
		rng := factory.NewEmptyRange(0)
		for _, lh := range hashes {
			if err := rng.Append(lh, nil); err != nil {
				c.fail("tree %q: compact Append: %v", t.Name, err)
			}
		}
		cr, err := rng.GetRootHash(nil)
		if err != nil {
			c.fail("tree %q: compact GetRootHash: %v", t.Name, err)
		}
		if len(hashes) == 0 {
			if cr != nil {
				c.fail("tree %q: compact range root of empty tree is %x, expected nil (upstream behaviour)", t.Name, cr)
			}
		} else if !bytes.Equal(cr, root) {
			c.fail("tree %q: compact.Range root %x, fixture %s", t.Name, cr, t.Root)
		}
		k := treeKey{t.TreeSize, t.Root}
		treesByKey[k] = append(treesByKey[k], mt)
		treeLeafHashes[mt] = leafHex
	}

	var computedDiscrepancies []string
	for _, in := range f.Inclusion {
		dup("inclusion", in.Name)
		c.inclusion++
		if strings.HasPrefix(in.Name, "generated:") {
			c.generatedCases++
		} else {
			c.publishedCases++
		}
		if in.Path == nil {
			c.fail("inclusion %q: path is null", in.Name)
		}
		leafHash := unhex(c, in.Name, in.LeafHash)
		root := unhex(c, in.Name, in.Root)
		path := unhexList(c, in.Name, in.Path)
		err := proof.VerifyInclusion(h, in.LeafIndex, in.TreeSize, leafHash, path, root)
		got := err == nil
		if got != in.Valid {
			c.fail("inclusion %q: fixture valid=%v, proof.VerifyInclusion valid=%v (%v)", in.Name, in.Valid, got, err)
		}
		if got {
			c.valid++
			calc, err := proof.RootFromInclusionProof(h, in.LeafIndex, in.TreeSize, leafHash, path)
			if err != nil || !bytes.Equal(calc, root) {
				c.fail("inclusion %q: RootFromInclusionProof %x (%v)", in.Name, calc, err)
			}
			// Prover: if the tree is in the file, the implementation must
			// produce exactly this path.
			for _, mt := range treesByKey[treeKey{in.TreeSize, in.Root}] {
				if treeLeafHashes[mt][in.LeafIndex] != in.LeafHash {
					continue
				}
				pp, err := mt.InclusionProof(in.LeafIndex, in.TreeSize)
				if err != nil || !pathsEqual(pp, path) {
					c.fail("inclusion %q: testonly.Tree.InclusionProof %x differs from fixture path (%v)", in.Name, pp, err)
				} else {
					c.proverConfirmed++
				}
				break
			}
		} else {
			c.invalid++
		}
		// Second verifier: trillian@v1.4.2 logverifier (int64 indexes; a
		// uint64 above MaxInt64 becomes negative there, as it did in the
		// int64-era Trillian tests that produced these corruptions).
		terr := tv.VerifyInclusionProof(int64(in.LeafIndex), int64(in.TreeSize), path, root, leafHash)
		if (terr == nil) != got {
			c.fail("inclusion %q: trillian@v1.4.2 logverifier valid=%v, transparency-dev valid=%v", in.Name, terr == nil, got)
		} else {
			c.trillianAgreed++
		}
		// RFC 9162 section 2.1.3.2, transcribed independently (rfc9162.go):
		// rfc9162_valid must be present exactly when it differs from the
		// implementation's verdict, and must be the RFC answer.
		rfc := rfc9162Verify(leafHash, in.LeafIndex, in.TreeSize, path, root, true)
		if rfc == got {
			c.rfcAgreed++
			if in.RFC9162Valid != nil {
				c.fail("inclusion %q: rfc9162_valid present but RFC 9162 agrees with the implementation", in.Name)
			}
		} else {
			computedDiscrepancies = append(computedDiscrepancies, in.Name+" (RFC 9162)")
			if in.RFC9162Valid == nil || *in.RFC9162Valid != rfc {
				c.fail("inclusion %q: RFC 9162 section 2.1.3.2 valid=%v, implementation valid=%v, rfc9162_valid must be %v", in.Name, rfc, got, rfc)
			}
		}
		if bare := rfc9162Verify(leafHash, in.LeafIndex, in.TreeSize, path, root, false); bare != rfc {
			c.bareRFCDiffers = append(c.bareRFCDiffers, in.Name)
		}
		switch in.UpstreamExpectation {
		case "valid", "invalid":
			if (in.UpstreamExpectation == "valid") != got {
				computedDiscrepancies = append(computedDiscrepancies, in.Name)
			}
		case "none":
		default:
			c.fail("inclusion %q: bad upstream_expectation %q", in.Name, in.UpstreamExpectation)
		}
	}
	c.discrepancies = len(computedDiscrepancies)
	if len(computedDiscrepancies) != len(f.Discrepancies) {
		c.fail("discrepancies: computed %d (%v), fixture lists %d", len(computedDiscrepancies), computedDiscrepancies, len(f.Discrepancies))
	}
	// The notes name exactly one case that only the typed reading rejects.
	if len(c.bareRFCDiffers) != 1 || !strings.Contains(c.bareRFCDiffers[0], "TestVerifyInclusionSingleEntry test:3") {
		c.fail("bare (untyped) RFC 9162 reading differs on %v, the notes name only TestVerifyInclusionSingleEntry test:3", c.bareRFCDiffers)
	}
}

// checkProofTestInclusion confirms, with the implementation's own functions,
// every fixture case materialized from proof/proof_test.go TestInclusion:
// leaf hash (rfc6962 HashLeaf of genEntries[index]), root (testonly.Tree
// over genEntries), and path (proof.Inclusion node IDs, hashed from the
// nodes compact.Range reports while appending, then proof.Nodes.Rehash).
func (c *checker) checkProofTestInclusion(f *Fixture) {
	h := rfc6962.DefaultHasher
	byName := map[string]*Inclusion{}
	for i := range f.Inclusion {
		byName[f.Inclusion[i].Name] = &f.Inclusion[i]
	}
	cases := proofTestInclusionCases()
	var max uint64
	for _, tc := range cases {
		if tc.size > max {
			max = tc.size
		}
		if tc.index+1 > max {
			max = tc.index + 1
		}
	}
	entries := genEntries(max)
	tree := testonly.New(h)
	tree.AppendData(entries...)
	nodeHash := map[compact.NodeID][]byte{}
	rng := (&compact.RangeFactory{Hash: h.HashChildren}).NewEmptyRange(0)
	for _, e := range entries {
		if err := rng.Append(h.HashLeaf(e), func(id compact.NodeID, hash []byte) { nodeHash[id] = hash }); err != nil {
			c.fail("TestInclusion: compact Append: %v", err)
		}
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		name := proofTestInclusionName(tc)
		if seen[name] {
			continue
		}
		seen[name] = true
		in := byName[name]
		if in == nil {
			c.fail("TestInclusion/%d:%d: no fixture case %q", tc.size, tc.index, name)
			continue
		}
		c.tiCases++
		if in.LeafIndex != tc.index || in.TreeSize != tc.size {
			c.fail("%s: index/size %d/%d", name, in.LeafIndex, in.TreeSize)
		}
		if in.LeafHash != hex.EncodeToString(h.HashLeaf(entries[tc.index])) {
			c.fail("%s: leaf hash is not HashLeaf(genEntries[%d])", name, tc.index)
		}
		if in.Root != hex.EncodeToString(tree.HashAt(tc.size)) {
			c.fail("%s: root is not testonly.Tree.HashAt(%d) over genEntries", name, tc.size)
		}
		if tc.wantErr {
			if len(in.Path) != 0 || in.Valid || in.UpstreamExpectation != "invalid" {
				c.fail("%s: error row must have an empty path, valid=false, expectation invalid", name)
			}
			continue
		}
		nodes, err := proof.Inclusion(tc.index, tc.size)
		if err != nil {
			c.fail("%s: proof.Inclusion: %v", name, err)
			continue
		}
		hashes := make([][]byte, len(nodes.IDs))
		for i, id := range nodes.IDs {
			if hashes[i] = nodeHash[id]; hashes[i] == nil {
				c.fail("%s: compact.Range reported no node %v", name, id)
			}
		}
		want, err := nodes.Rehash(hashes, h.HashChildren)
		if err != nil || !pathsEqual(want, unhexList(c, name, in.Path)) {
			c.fail("%s: proof.Nodes.Rehash path %x differs from the fixture (%v)", name, want, err)
		}
		if tp, err := tree.InclusionProof(tc.index, tc.size); err != nil || !pathsEqual(tp, want) {
			c.fail("%s: testonly.Tree.InclusionProof %x differs (%v)", name, tp, err)
		}
		if !in.Valid || in.UpstreamExpectation != "none" {
			c.fail("%s: valid row must be valid with expectation none", name)
		}
	}
	for _, tc := range cases {
		if tc.wantErr || tc.size <= generatedMaxSize {
			continue
		}
		found := false
		for _, t := range f.Trees {
			if t.Name == proofTestInclusionTreeName(tc.size) {
				found = t.TreeSize == tc.size && t.Root == hex.EncodeToString(tree.HashAt(tc.size))
			}
		}
		if !found {
			c.fail("TestInclusion: tree of size %d over genEntries missing or wrong", tc.size)
		}
	}
}

// checkSubtreeVectors reproduces the two digests of transparency-dev/merkle
// main testonly/vectors_test.go (TestSubtreeHashVectors and
// TestSubtreeInclusionProofVectors) over their full row sets, twice: with the
// implementation (a testonly.Tree over each leaf range D[start:], so that
// subtree [start, end) is HashAt(end - start) and its inclusion proof is
// InclusionProof(index - start, end - start)), and with the verbatim
// reference functions (refRootHash, refInclusionProof) on indepHasher. That
// is the RFC 9162 section 2.1 reading of a subtree: MTH(D[start:end]) and
// PATH(index - start, D[start:end]).
func (c *checker) checkSubtreeVectors() {
	h := rfc6962.DefaultHasher
	entries := subtreeVectorEntries()
	trees := make([]*testonly.Tree, len(entries)+1)
	for s := range trees {
		trees[s] = testonly.New(h)
		trees[s].AppendData(entries[s:]...)
	}
	impl := struct {
		hash  func(start, end uint64) []byte
		proof func(index, start, end uint64) ([][]byte, error)
	}{
		hash: func(start, end uint64) []byte { return trees[start].HashAt(end - start) },
		proof: func(index, start, end uint64) ([][]byte, error) {
			return trees[start].InclusionProof(index-start, end-start)
		},
	}
	ref := struct {
		hash  func(start, end uint64) []byte
		proof func(index, start, end uint64) ([][]byte, error)
	}{
		hash: func(start, end uint64) []byte { return refRootHash(entries[start:end], ih) },
		proof: func(index, start, end uint64) ([][]byte, error) {
			return refInclusionProof(entries[start:end], index-start, ih), nil
		},
	}
	for _, v := range []struct {
		name  string
		hash  func(start, end uint64) []byte
		proof func(index, start, end uint64) ([][]byte, error)
	}{
		{"implementation (testonly.Tree over D[start:])", impl.hash, impl.proof},
		{"reference (refRootHash, refInclusionProof on crypto/sha256)", ref.hash, ref.proof},
	} {
		got, rows, err := subtreeHashVectorsDigest(v.hash)
		if err != nil || got != subtreeHashVectorsWant {
			c.fail("main vectors_test.go TestSubtreeHashVectors via %s: digest %s over %d rows, want %s (%v)", v.name, got, rows, subtreeHashVectorsWant, err)
		} else {
			c.svDigests++
		}
		c.svHashRows = rows
		start0 := 0
		counting := func(index, start, end uint64) ([][]byte, error) {
			if start == 0 {
				start0++
			}
			return v.proof(index, start, end)
		}
		got, rows, err = subtreeInclusionProofVectorsDigest(counting)
		if err != nil || got != subtreeInclusionProofVectorsWant {
			c.fail("main vectors_test.go TestSubtreeInclusionProofVectors via %s: digest %s over %d rows, want %s (%v)", v.name, got, rows, subtreeInclusionProofVectorsWant, err)
		} else {
			c.svDigests++
		}
		c.svProofRows, c.svStart0Rows = rows, start0
	}
	if want := int(subtreeVectorMax * (subtreeVectorMax + 1) / 2); c.svStart0Rows != want {
		c.fail("main vectors_test.go TestSubtreeInclusionProofVectors: %d start = 0 rows, want %d", c.svStart0Rows, want)
	}
}

// checkSubtreeVectorRows confirms, with the implementation's own functions,
// every start = 0 row of TestSubtreeInclusionProofVectors that the fixture
// lists (exactly subtreeVectorRows(), nothing more), and the size-130 tree:
// leaf hash, root (testonly.Tree.HashAt) and path
// (testonly.Tree.InclusionProof) over d[i] = i. checkSubtreeVectors ties the
// same functions to the published digest.
func (c *checker) checkSubtreeVectorRows(f *Fixture) {
	h := rfc6962.DefaultHasher
	entries := subtreeVectorEntries()
	tree := testonly.New(h)
	tree.AppendData(entries...)
	want := map[string]subtreeVectorRow{}
	for _, r := range subtreeVectorRows() {
		want[subtreeVectorCaseName(r)] = r
	}
	for _, in := range f.Inclusion {
		if !strings.HasPrefix(in.Name, pVectors+" TestSubtreeInclusionProofVectors") {
			continue
		}
		r, ok := want[in.Name]
		if !ok {
			c.fail("%s: not a row of subtreeVectorRows()", in.Name)
			continue
		}
		delete(want, in.Name)
		if in.LeafIndex != r.index || in.TreeSize != r.size {
			c.fail("%s: index/size %d/%d", in.Name, in.LeafIndex, in.TreeSize)
			continue
		}
		if in.LeafHash != hex.EncodeToString(tree.LeafHash(r.index)) || in.LeafHash != hex.EncodeToString(h.HashLeaf(entries[r.index])) {
			c.fail("%s: leaf hash is not HashLeaf(d[%d])", in.Name, r.index)
		}
		if in.Root != hex.EncodeToString(tree.HashAt(r.size)) {
			c.fail("%s: root is not testonly.Tree.HashAt(%d) over d[i] = i", in.Name, r.size)
		}
		p, err := tree.InclusionProof(r.index, r.size)
		if err != nil || !pathsEqual(p, unhexList(c, in.Name, in.Path)) {
			c.fail("%s: testonly.Tree.InclusionProof %x differs from the fixture path (%v)", in.Name, p, err)
		}
		if !in.Valid || in.UpstreamExpectation != "none" {
			c.fail("%s: must be valid with upstream_expectation none", in.Name)
		}
		c.svCases++
	}
	for name := range want {
		c.fail("missing fixture case %q", name)
	}
	found := false
	for _, t := range f.Trees {
		if t.Name != subtreeVectorTreeName {
			continue
		}
		found = true
		if t.TreeSize != subtreeVectorMax || t.Root != hex.EncodeToString(tree.Hash()) || len(t.LeafData) != len(entries) {
			c.fail("tree %q: size %d, root %s, %d leaves; want %d leaves d[i] = i with root %x", t.Name, t.TreeSize, t.Root, len(t.LeafData), subtreeVectorMax, tree.Hash())
			continue
		}
		for i, d := range t.LeafData {
			if d != hex.EncodeToString(entries[i]) {
				c.fail("tree %q: leaf_data[%d] = %s, want %x", t.Name, i, d, entries[i])
			}
		}
	}
	if !found {
		c.fail("missing tree %q", subtreeVectorTreeName)
	}
}

// mainProbe is the JSON shape of testdata/inclusion on transparency-dev/merkle
// main (proof/verify_test.go:30-39 at fbbcd741c3d1, type inclusionProbe).
type mainProbe struct {
	LeafIdx   uint64   `json:"leafIdx"`
	TreeSize  uint64   `json:"treeSize"`
	Root      []byte   `json:"root"`
	LeafHash  []byte   `json:"leafHash"`
	Proof     [][]byte `json:"proof"`
	Desc      string   `json:"desc"`
	WantError bool     `json:"wantErr"`
}

// mainTestdata is the copy of transparency-dev/merkle main
// testdata/inclusion (see testdata/upstream-main-inclusion/SOURCE.txt and
// LICENSE), embedded so the program reads nothing at run time except the
// -fixtures file.
//
//go:embed testdata/upstream-main-inclusion
var mainTestdata embed.FS

const mainTestdataDir = "testdata/upstream-main-inclusion"

// checkMainTestdata matches upstream's own JSON materialization (main
// branch) one for one against the fixture cases named
// "published: proof/verify_test.go".
func (c *checker) checkMainTestdata(f *Fixture) {
	pool := map[string]int{}
	key := func(idx, size uint64, leaf, root []byte, path [][]byte, valid bool) string {
		var sb strings.Builder
		fmt.Fprintf(&sb, "%d|%d|%x|%x|%v", idx, size, leaf, root, valid)
		for _, p := range path {
			fmt.Fprintf(&sb, "|%x", p)
		}
		return sb.String()
	}
	for _, in := range f.Inclusion {
		if !strings.HasPrefix(in.Name, pVerify) {
			continue
		}
		pool[key(in.LeafIndex, in.TreeSize, unhex(c, in.Name, in.LeafHash), unhex(c, in.Name, in.Root), unhexList(c, in.Name, in.Path), in.Valid)]++
	}
	total := 0
	for _, n := range pool {
		total += n
	}
	var files []string
	err := fs.WalkDir(mainTestdata, mainTestdataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && path.Ext(p) == ".json" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		c.fail("main testdata: %v", err)
		return
	}
	sort.Strings(files)
	c.mainFiles = len(files)
	for _, p := range files {
		data, err := mainTestdata.ReadFile(p)
		if err != nil {
			c.fail("main testdata %s: %v", p, err)
			continue
		}
		var mp mainProbe
		if err := json.Unmarshal(data, &mp); err != nil {
			c.fail("main testdata %s: %v", p, err)
			continue
		}
		k := key(mp.LeafIdx, mp.TreeSize, mp.LeafHash, mp.Root, mp.Proof, !mp.WantError)
		if pool[k] == 0 {
			c.fail("main testdata %s (%q) has no matching fixture case", p, mp.Desc)
			continue
		}
		pool[k]--
		c.mainMatched++
	}
	if c.mainMatched != total {
		c.fail("main testdata: matched %d of %d fixture cases named %q", c.mainMatched, total, pVerify)
	}
}

func canonical(f *Fixture) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// checkRegeneration requires the file to be exactly what build() produces
// from the verbatim upstream literals: nothing missing, nothing extra,
// nothing edited by hand.
func (c *checker) checkRegeneration(raw []byte, f *Fixture) {
	want := build()
	if bytes.Equal(raw, canonical(want)) {
		return
	}
	switch {
	case len(f.HashChecks) != len(want.HashChecks):
		c.fail("regeneration: %d hash checks in file, %d from upstream literals", len(f.HashChecks), len(want.HashChecks))
	case len(f.Trees) != len(want.Trees):
		c.fail("regeneration: %d trees in file, %d from upstream literals", len(f.Trees), len(want.Trees))
	case len(f.Inclusion) != len(want.Inclusion):
		c.fail("regeneration: %d inclusion cases in file, %d from upstream literals", len(f.Inclusion), len(want.Inclusion))
	}
	for i := range want.HashChecks {
		if i < len(f.HashChecks) && !reflect.DeepEqual(f.HashChecks[i], want.HashChecks[i]) {
			c.fail("regeneration: hash_checks[%d] %q differs", i, want.HashChecks[i].Name)
			return
		}
	}
	for i := range want.Trees {
		if i < len(f.Trees) && !reflect.DeepEqual(f.Trees[i], want.Trees[i]) {
			c.fail("regeneration: trees[%d] %q differs", i, want.Trees[i].Name)
			return
		}
	}
	for i := range want.Inclusion {
		if i < len(f.Inclusion) && !reflect.DeepEqual(f.Inclusion[i], want.Inclusion[i]) {
			c.fail("regeneration: inclusion[%d] %q differs", i, want.Inclusion[i].Name)
			return
		}
	}
	c.fail("regeneration: file differs from build() output (metadata, notes or formatting)")
}
