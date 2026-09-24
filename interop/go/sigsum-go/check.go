// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/types"
)

// maxRuleTreeSize bounds a leaf_data_rule tree, so that a malformed file
// cannot make the check loop for ever. The largest such tree is size 100.
const maxRuleTreeSize = 1 << 16

func decodeHash(s string) (crypto.Hash, error) {
	if s != strings.ToLower(s) {
		return crypto.Hash{}, fmt.Errorf("hex %q is not lowercase", s)
	}
	return crypto.HashFromHex(s)
}

func decodeBytes(s string) ([]byte, error) {
	if s != strings.ToLower(s) {
		return nil, fmt.Errorf("hex %q is not lowercase", s)
	}
	return hex.DecodeString(s)
}

// ruleData is the leaf data a leaf_data_rule gives for index i.
func ruleData(r *LeafDataRule, i uint64) ([]byte, error) {
	switch r.Encoding {
	case "u64be":
		return u64be(i), nil
	}
	return nil, fmt.Errorf("unknown leaf_data_rule encoding %q", r.Encoding)
}

// checkedTree is a tree of the file that passed its checks, and the
// implementation's audit path for each of its leaves: merkle.Tree.ProveInclusion,
// or sigsumPath for a tree with duplicate leaves.
type checkedTree struct {
	leaves []crypto.Hash
	prove  func(index, size uint64) ([]crypto.Hash, error)
}

// check verifies the file entry by entry with sigsum-go's own functions,
// re-runs the upstream assertions, and finally requires the file to be
// byte-identical to what build() regenerates.
func check(path string) (string, []string) {
	var fails []string
	failf := func(format string, args ...any) { fails = append(fails, fmt.Sprintf(format, args...)) }

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", []string{fmt.Sprintf("read %s: %v", path, err)}
	}
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return "", []string{fmt.Sprintf("decode %s: %v", path, err)}
	}
	if dec.More() {
		failf("trailing data after the JSON object")
	}
	if f.Implementation != implementation || f.Version != version || f.License != license {
		failf("header is %q %q %q, want %q %q %q", f.Implementation, f.Version, f.License, implementation, version, license)
	}

	prefixOK := func(name string) (published bool, ok bool) {
		switch {
		case strings.HasPrefix(name, "published: "):
			return true, true
		case strings.HasPrefix(name, "generated: "):
			return false, true
		}
		return false, false
	}
	published, generated := 0, 0
	count := func(name, where string) {
		p, ok := prefixOK(name)
		if !ok {
			failf("%s %q: name must start with \"published: \" or \"generated: \"", where, name)
			return
		}
		if p {
			published++
		} else {
			generated++
		}
	}

	// empty_root
	empty := merkle.HashEmptyTree()
	emptyTree := merkle.NewTree()
	if f.EmptyRoot == nil {
		failf("empty_root is null")
	} else if *f.EmptyRoot != hh(empty) || *f.EmptyRoot != hh(emptyTree.GetRootHash()) || *f.EmptyRoot != hh(refMTH(nil)) {
		failf("empty_root %s is not merkle.HashEmptyTree() = NewTree().GetRootHash() = SHA-256(\"\")", *f.EmptyRoot)
	}

	// hash_checks
	leafChecks, nodeChecks := 0, 0
	for _, c := range f.HashChecks {
		count(c.Name, "hash_check")
		want, err := decodeHash(c.Hash)
		if err != nil {
			failf("hash_check %q: hash: %v", c.Name, err)
			continue
		}
		switch c.Kind {
		case "leaf":
			if c.InputHex == nil || c.Left != nil || c.Right != nil {
				failf("hash_check %q: a leaf check needs input_hex only", c.Name)
				continue
			}
			in, err := decodeBytes(*c.InputHex)
			if err != nil {
				failf("hash_check %q: input_hex: %v", c.Name, err)
				continue
			}
			if merkle.HashLeafNode(in) != want {
				failf("hash_check %q: merkle.HashLeafNode(input) = %s, file says %s", c.Name, hh(merkle.HashLeafNode(in)), c.Hash)
			}
			if refLeaf(in) != h32(want) {
				failf("hash_check %q: RFC 9162 leaf hash disagrees", c.Name)
			}
			leafChecks++
		case "node":
			if c.InputHex != nil || c.Left == nil || c.Right == nil {
				failf("hash_check %q: a node check needs left and right only", c.Name)
				continue
			}
			l, err1 := decodeHash(*c.Left)
			r, err2 := decodeHash(*c.Right)
			if err1 != nil || err2 != nil {
				failf("hash_check %q: left/right: %v %v", c.Name, err1, err2)
				continue
			}
			if merkle.HashInteriorNode(&l, &r) != want {
				failf("hash_check %q: merkle.HashInteriorNode(left, right) = %s, file says %s", c.Name, hh(merkle.HashInteriorNode(&l, &r)), c.Hash)
			}
			if refNode(h32(l), h32(r)) != h32(want) {
				failf("hash_check %q: RFC 9162 node hash disagrees", c.Name)
			}
			nodeChecks++
		default:
			failf("hash_check %q: unknown kind %q", c.Name, c.Kind)
		}
	}

	// trees
	trees := map[string]*checkedTree{}
	treePaths, dupTrees := 0, 0
	for _, t := range f.Trees {
		count(t.Name, "tree")
		var leaves []crypto.Hash
		switch {
		case t.LeafDataRule != nil:
			if t.LeafData != nil || t.LeafHashes != nil {
				failf("tree %q: with leaf_data_rule, leaf_data and leaf_hashes must be null", t.Name)
				continue
			}
			if t.TreeSize > maxRuleTreeSize {
				failf("tree %q: tree_size %d is over %d", t.Name, t.TreeSize, maxRuleTreeSize)
				continue
			}
			bad := false
			for i := uint64(0); i < t.TreeSize; i++ {
				d, err := ruleData(t.LeafDataRule, t.LeafDataRule.First+i)
				if err != nil {
					failf("tree %q: %v", t.Name, err)
					bad = true
					break
				}
				leaves = append(leaves, merkle.HashLeafNode(d))
			}
			if bad {
				continue
			}
		case t.LeafHashes != nil:
			bad := false
			for _, s := range t.LeafHashes {
				h, err := decodeHash(s)
				if err != nil {
					failf("tree %q: leaf hash: %v", t.Name, err)
					bad = true
				}
				leaves = append(leaves, h)
			}
			if bad {
				continue
			}
			if t.LeafData != nil {
				if len(t.LeafData) != len(t.LeafHashes) {
					failf("tree %q: %d leaf_data but %d leaf_hashes", t.Name, len(t.LeafData), len(t.LeafHashes))
					continue
				}
				for i, s := range t.LeafData {
					d, err := decodeBytes(s)
					if err != nil || merkle.HashLeafNode(d) != leaves[i] {
						failf("tree %q: leaf %d: merkle.HashLeafNode(leaf_data) is not leaf_hashes[%d] (%v)", t.Name, i, i, err)
					}
				}
			}
		default:
			failf("tree %q: neither leaf_hashes nor leaf_data_rule", t.Name)
			continue
		}
		if uint64(len(leaves)) != t.TreeSize {
			failf("tree %q: %d leaves, tree_size %d", t.Name, len(leaves), t.TreeSize)
			continue
		}
		root, err := decodeHash(t.Root)
		if err != nil {
			failf("tree %q: root: %v", t.Name, err)
			continue
		}
		ct := &checkedTree{leaves: leaves}
		if dupAt := firstDuplicate(leaves); dupAt < 0 {
			tr := merkle.NewTree()
			for i := range leaves {
				tr.AddLeafHash(&leaves[i])
			}
			if tr.GetRootHash() != root {
				failf("tree %q: merkle.Tree root %s, file says %s", t.Name, hh(tr.GetRootHash()), t.Root)
			}
			ct.prove = tr.ProveInclusion
		} else {
			// merkle.Tree cannot hold this tree: AddLeafHash refuses the
			// first repeated leaf hash (pkg/merkle/tree.go:64-68).
			tr := merkle.NewTree()
			for i := 0; i < dupAt; i++ {
				tr.AddLeafHash(&leaves[i])
			}
			if tr.AddLeafHash(&leaves[dupAt]) || tr.Size() != uint64(dupAt) {
				failf("tree %q: merkle.Tree.AddLeafHash accepted the repeated leaf %d", t.Name, dupAt)
			}
			// Built with sigsum's hash functions, and checked with
			// merkle.VerifyInclusionTail, whose compact range code takes every
			// leaf as given: leaf 0's path over all the leaves reaches the root.
			if sigsumMTH(leaves) != root {
				failf("tree %q: root built with sigsum's hash functions is %s, file says %s", t.Name, hh(sigsumMTH(leaves)), t.Root)
			}
			if err := merkle.VerifyInclusionTail(slices.Clone(leaves), 0, &root, sigsumPath(0, leaves)); err != nil {
				failf("tree %q: merkle.VerifyInclusionTail over all %d leaves: %v", t.Name, len(leaves), err)
			}
			ct.prove = func(index, size uint64) ([]crypto.Hash, error) {
				if index >= size || size != uint64(len(leaves)) {
					return nil, fmt.Errorf("index %d, size %d, tree %d", index, size, len(leaves))
				}
				return sigsumPath(int(index), leaves), nil
			}
			dupTrees++
		}
		if refMTH(toH32s(leaves)) != h32(root) {
			failf("tree %q: RFC 9162 MTH disagrees", t.Name)
		}
		for i := range leaves {
			p, err := ct.prove(uint64(i), t.TreeSize)
			if err != nil {
				failf("tree %q: proving leaf %d: %v", t.Name, i, err)
				continue
			}
			if !verify(leaves[i], uint64(i), t.TreeSize, root, p) {
				failf("tree %q: merkle.VerifyInclusion rejects the path of leaf %d", t.Name, i)
			}
			if !slices.Equal(toH32s(p), refPath(i, toH32s(leaves))) {
				failf("tree %q: the path of leaf %d is not RFC 9162 PATH", t.Name, i)
			}
			treePaths++
		}
		trees[fmt.Sprintf("%s/%d", t.Root, t.TreeSize)] = ct
	}

	// inclusion
	valid, invalid, proverChecked, ivPairs, probeCount, dupCases := 0, 0, 0, 0, 0, 0
	disc := strings.Join(f.Discrepancies, "\n")
	for _, c := range f.Inclusion {
		count(c.Name, "inclusion")
		if strings.HasPrefix(c.Name, ivPrefix) && c.UpstreamExpectation == "valid" {
			ivPairs++
		}
		if strings.HasPrefix(c.Name, "generated: probe ") {
			probeCount++
		}
		if strings.HasPrefix(c.Name, dupPrefix) {
			dupCases++
		}
		leaf, err1 := decodeHash(c.LeafHash)
		root, err2 := decodeHash(c.Root)
		if err1 != nil || err2 != nil {
			failf("inclusion %q: leaf_hash/root: %v %v", c.Name, err1, err2)
			continue
		}
		if c.Path == nil {
			failf("inclusion %q: path is null", c.Name)
			continue
		}
		var path []crypto.Hash
		bad := false
		for _, s := range c.Path {
			h, err := decodeHash(s)
			if err != nil {
				failf("inclusion %q: path: %v", c.Name, err)
				bad = true
				break
			}
			path = append(path, h)
		}
		if bad {
			continue
		}
		got := verify(leaf, c.LeafIndex, c.TreeSize, root, path)
		if got != c.Valid {
			failf("inclusion %q: merkle.VerifyInclusion says %v, file says %v", c.Name, got, c.Valid)
		}
		if got {
			valid++
		} else {
			invalid++
		}
		ref := refVerify(h32(leaf), c.LeafIndex, c.TreeSize, h32(root), toH32s(path))
		if c.RFC9162Valid != nil {
			if ref != *c.RFC9162Valid || *c.RFC9162Valid == c.Valid {
				failf("inclusion %q: rfc9162_valid %v, but RFC 9162 2.1.3.2 says %v and valid is %v", c.Name, *c.RFC9162Valid, ref, c.Valid)
			}
		} else if ref != c.Valid {
			failf("inclusion %q: RFC 9162 2.1.3.2 says %v, valid is %v and rfc9162_valid is missing", c.Name, ref, c.Valid)
		}
		switch c.UpstreamExpectation {
		case "none":
		case "valid", "invalid":
			if (c.UpstreamExpectation == "valid") != got && !strings.Contains(disc, c.Name) {
				failf("inclusion %q: upstream expects %s but the verifier says %v, and discrepancies does not name it", c.Name, c.UpstreamExpectation, got)
			}
		default:
			failf("inclusion %q: upstream_expectation %q", c.Name, c.UpstreamExpectation)
		}
		if got {
			if ct, ok := trees[fmt.Sprintf("%s/%d", c.Root, c.TreeSize)]; ok {
				if c.LeafIndex >= uint64(len(ct.leaves)) || ct.leaves[c.LeafIndex] != leaf {
					failf("inclusion %q: leaf_hash is not leaf %d of the file's tree with this root", c.Name, c.LeafIndex)
				} else if p, err := ct.prove(c.LeafIndex, c.TreeSize); err != nil || !slices.Equal(p, path) {
					failf("inclusion %q: path is not the tree's own path for leaf %d at size %d (%v)", c.Name, c.LeafIndex, c.TreeSize, err)
				} else {
					proverChecked++
				}
			}
		}
	}

	// Upstream assertions, deviations and RFC 9162 conformance.
	ua, uaFails := upstreamAssertions()
	fails = append(fails, uaFails...)

	// The file must be exactly what build() regenerates.
	identical := false
	if want, err := build(); err != nil {
		failf("build: %v", err)
	} else if wb, err := marshal(want); err != nil {
		failf("marshal: %v", err)
	} else if !bytes.Equal(wb, raw) {
		gl, wl := strings.Split(string(raw), "\n"), strings.Split(string(wb), "\n")
		located := false
		for i := 0; i < len(gl) || i < len(wl); i++ {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				col := 0
				for col < len(g) && col < len(w) && g[col] == w[col] {
					col++
				}
				from := max(0, col-40)
				failf("file differs from the regenerated fixture at line %d, byte %d: the file has %.100q, -write would write %.100q", i+1, col+1, g[from:], w[from:])
				located = true
				break
			}
		}
		if !located {
			failf("file differs from the regenerated fixture only in its line endings: %d bytes, -write would write %d", len(raw), len(wb))
		}
	} else {
		identical = true
	}

	summary := fmt.Sprintf("empty_root 1, hash_checks %d (leaf %d, node %d), trees %d (every leaf re-proved: %d paths; duplicate-leaf trees %d), inclusion %d (valid %d, invalid %d; TestInclusionValid %d of 5050 pairs, probes %d, duplicate-leaf tree %d; %d valid paths equal the tree's own path), published %d, generated %d; RFC 9162 reference agrees on every case; %s; file byte-identical to regeneration: %v",
		len(f.HashChecks), leafChecks, nodeChecks, len(f.Trees), treePaths, dupTrees, len(f.Inclusion), valid, invalid, ivPairs, probeCount, dupCases, proverChecked, published, generated, ua, identical)
	return summary, fails
}

// runUpstreamTest runs a copied upstream test body. Each t.Errorf it makes,
// and a t.Fatalf (which panics), becomes one failure named after the test.
func runUpstreamTest(name string, body func(t fatalT)) (fails []string) {
	var errs []string
	defer func() {
		if r := recover(); r != nil {
			errs = append(errs, fmt.Sprint(r))
		}
		for _, e := range errs {
			fails = append(fails, name+": "+e)
		}
	}()
	body(fatalT{errs: &errs})
	return nil
}

// upstreamAssertions re-runs what upstream asserts, the duplicate-leaf API
// deviation, the doc/tools.md examples, and RFC 9162 conformance of sigsum's
// roots and paths.
func upstreamAssertions() (string, []string) {
	var fails []string
	failf := func(format string, args ...any) { fails = append(fails, fmt.Sprintf(format, args...)) }

	// TestASCII: FromASCII then ToASCII gives the same text.
	for _, tc := range testASCIITable {
		p, err := parseProof(tc.ascii)
		if err != nil {
			failf("TestASCII %s: FromASCII: %v", tc.desc, err)
			continue
		}
		var buf bytes.Buffer
		if err := p.ToASCII(&buf); err != nil || buf.String() != tc.ascii {
			failf("TestASCII %s: round trip differs (%v)", tc.desc, err)
		}
	}
	// TestASCIIV1: the version 1 text reads as the version 2 proof, and its
	// short checksum is the first 2 bytes of SHA-256 of the reconstructed message.
	for i, tc := range testASCIIV1Table {
		p, err := parseProof(tc.asciiV1)
		if err != nil {
			failf("TestASCIIV1 %s: FromASCII: %v", tc.desc, err)
			continue
		}
		var buf bytes.Buffer
		if err := p.ToASCII(&buf); err != nil || buf.String() != tc.asciiV2 {
			failf("TestASCIIV1 %s: v1 does not read as v2 (%v)", tc.desc, err)
		}
		if tc.asciiV2 != testASCIITable[i].ascii {
			failf("TestASCIIV1 %s is not the TestASCII proof", tc.desc)
		}
		x := []int{1, 4}[i]
		msg := submitTestMessage(x)
		sum := crypto.HashBytes(msg[:])
		short := ""
		for _, line := range strings.Split(tc.asciiV1, "\n") {
			if strings.HasPrefix(line, "leaf=") {
				short = strings.Fields(strings.TrimPrefix(line, "leaf="))[0]
			}
		}
		if short != hex.EncodeToString(sum[:2]) {
			failf("TestASCIIV1 %s: short checksum %s is not the prefix of SHA-256(foo-%d message) %s", tc.desc, short, x, hh(sum))
		}
	}

	rps, err := realProofs()
	if err != nil {
		return "", append(fails, err.Error())
	}
	// Every real proof verifies through types.InclusionProof.Verify.
	for _, rp := range rps {
		if err := rp.sp.Inclusion.Verify(&rp.leafHash, &rp.sp.TreeHead.TreeHead); err != nil {
			failf("%s: types.InclusionProof.Verify: %v", rp.label, err)
		}
	}
	if rps[0].leafHash != rps[0].sp.TreeHead.RootHash {
		failf("TestASCII size 1: the reconstructed leaf hash is not the root_hash literal")
	}
	// TestVerifyNoCosignatures and TestVerify: the full Sigsum verification.
	full := 0
	{
		ascii, msg, logKey, submitKey := testVerifyNoCosignaturesInputs()
		p, err := parseProof(ascii)
		if err == nil {
			err = p.VerifyNoCosignatures(&msg, map[crypto.Hash]crypto.PublicKey{
				crypto.HashBytes(submitKey[:]): submitKey}, &logKey)
		}
		if err != nil {
			failf("TestVerifyNoCosignatures: %v", err)
		} else {
			full++
		}
		pub, sth := testSignedTreeHeadVerifyInputs()
		if !sth.Verify(&pub) || sth.RootHash != p.TreeHead.RootHash || sth.Size != p.TreeHead.Size || pub != logKey {
			failf("TestSignedTreeHeadVerify (tree_head_test.go:151-167) is not the TestVerifyNoCosignatures tree head")
		}
	}
	{
		ascii, msg, logKey, submitKey, witnessKey := testVerifyInputs()
		p, err := parseProof(ascii)
		if err == nil {
			var pol *policy.Policy
			pol, err = policy.NewKofNPolicy([]crypto.PublicKey{logKey}, []crypto.PublicKey{witnessKey}, 1)
			if err == nil {
				err = p.Verify(&msg, map[crypto.Hash]crypto.PublicKey{
					crypto.HashBytes(submitKey[:]): submitKey}, pol)
			}
		}
		if err != nil {
			failf("TestVerify: %v", err)
		} else {
			full++
		}
	}

	// doc/tools.md: both Merkle proofs verify and the two tree heads are
	// consistent, but under v0.14.1 neither the leaf signatures nor the tree
	// head signatures verify, which is why their upstream_expectation is "none".
	docMerkle, docUnsigned := 0, 0
	if doc, err := parseDocExamples(); err != nil {
		failf("doc/tools.md: %v", err)
	} else {
		keys := map[crypto.Hash]crypto.PublicKey{crypto.HashBytes(doc.submitKey[:]): doc.submitKey}
		for _, rp := range doc.proofs {
			if err := rp.sp.Inclusion.Verify(&rp.leafHash, &rp.sp.TreeHead.TreeHead); err != nil {
				failf("%s: types.InclusionProof.Verify: %v", rp.where, err)
			} else {
				docMerkle++
			}
			sth := types.SignedTreeHead{TreeHead: rp.sp.TreeHead.TreeHead, Signature: rp.sp.TreeHead.Signature}
			leafSig := rp.leaf.Verify(&doc.submitKey)
			headSig := sth.Verify(&doc.logKey)
			fullErr := rp.sp.VerifyNoCosignatures(&rp.msg, keys, &doc.logKey)
			if leafSig || headSig || fullErr == nil {
				failf("%s: expected the leaf and tree head signatures not to verify under v0.14.1; leaf %v, tree head %v, VerifyNoCosignatures %v", rp.where, leafSig, headSig, fullErr)
			} else {
				docUnsigned++
			}
		}
		if _, err := doc.request.Verify(); err == nil {
			failf("doc/tools.md:447-449: expected the request signature not to verify under v0.14.1")
		}
		p3, p4 := doc.proofs[0], doc.proofs[1]
		cons := []crypto.Hash{p3.leafHash, p4.leafHash, p3.sp.Inclusion.Path[0]}
		if err := merkle.VerifyConsistency(3, 4, &p3.sp.TreeHead.RootHash, &p4.sp.TreeHead.RootHash, cons); err != nil {
			failf("doc/tools.md: merkle.VerifyConsistency(3, 4) with [size 3 leaf hash, size 4 leaf hash, size 3 node_hash]: %v", err)
		}
	}

	// TestGetRootHash (tree_test.go:62-87) and TestInclusion
	// (tree_test.go:89-118), their bodies copied unchanged into upstream.go.
	fails = append(fails, runUpstreamTest("TestGetRootHash", testGetRootHash)...)
	fails = append(fails, runUpstreamTest("TestInclusion", testInclusion)...)
	hashes := newLeaves(5)

	// TestInclusionValid, all 5050 proofs and 5050 corruptions.
	cases, errs := materializeInclusionValid()
	for _, e := range errs {
		failf("TestInclusionValid: %s", strings.TrimSpace(e))
	}
	nv, nc := 0, 0
	for _, c := range cases {
		got := verify(c.leaf, uint64(c.i), uint64(c.n), c.root, c.proof)
		ref := refVerify(h32(c.leaf), uint64(c.i), uint64(c.n), h32(c.root), toH32s(c.proof))
		wantValid := c.bitToFlip < 0
		if got != wantValid || ref != wantValid {
			failf("TestInclusionValid i=%d n=%d flip=%d/%d: sigsum %v, RFC 9162 %v, upstream wants %v", c.i, c.n, c.bitToFlip, c.target, got, ref, wantValid)
		}
		if wantValid {
			nv++
		} else {
			nc++
		}
	}
	if nv != 5050 || nc != 5050 {
		failf("TestInclusionValid: %d proofs and %d corruptions, want 5050 each", nv, nc)
	}

	// Deviation: merkle.Tree refuses a duplicate leaf hash.
	dt := merkle.NewTree()
	l0 := hashes[0]
	if !dt.AddLeafHash(&l0) || dt.AddLeafHash(&l0) || dt.Size() != 1 || dt.GetRootHash() != l0 {
		failf("duplicate leaf: merkle.Tree.AddLeafHash did not refuse the second copy")
	}
	// merkle.VerifyInclusion itself accepts a proof in a tree with duplicates.
	if !verify(l0, 1, 2, node(l0, l0), []crypto.Hash{l0}) {
		failf("duplicate leaf: merkle.VerifyInclusion rejects leaf 1 of [l0, l0]")
	}

	// RFC 9162 conformance over newLeaves(100): every root and every path.
	leaves := newLeaves(100)
	big := merkle.NewTree()
	roots := 0
	for n := 0; n <= 100; n++ {
		if n > 0 {
			big.AddLeafHash(&leaves[n-1])
		}
		if h32(big.GetRootHash()) != refMTH(toH32s(leaves[:n])) {
			failf("conformance: root of size %d is not RFC 9162 MTH", n)
		}
		roots++
	}
	paths := 0
	for n := 1; n <= 100; n++ {
		for i := 0; i < n; i++ {
			p, err := big.ProveInclusion(uint64(i), uint64(n))
			if err != nil || !slices.Equal(toH32s(p), refPath(i, toH32s(leaves[:n]))) {
				failf("conformance: ProveInclusion(%d, %d) is not RFC 9162 PATH (%v)", i, n, err)
			}
			paths++
		}
	}

	return fmt.Sprintf("upstream assertions: TestASCII 2, TestASCIIV1 2, full proof.Verify %d, TestGetRootHash 6, TestInclusion 5, TestInclusionValid %d proofs + %d corruptions; doc/tools.md examples: Merkle proofs verify %d, consistency 3 to 4 verifies, leaf and tree head signatures do not verify under v0.14.1 %d; duplicate-leaf refusal confirmed; RFC 9162 conformance %d roots, %d paths",
		full, nv, nc, docMerkle, docUnsigned, roots, paths), fails
}
