// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// An independent RFC 9162 section 2.1 reference, written from the RFC text
// with crypto/sha256 only, used to decide whether tlog deviates anywhere.
// It never produces fixture values; it only has to agree with tlog.

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

func rfcNode(l, r tlog.Hash) tlog.Hash {
	b := make([]byte, 0, 65)
	b = append(b, 0x01)
	b = append(b, l[:]...)
	b = append(b, r[:]...)
	return sha256.Sum256(b)
}

// largest power of two strictly smaller than n (n >= 2)
func rfcSplit(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// RFC 9162 2.1.1 MTH over leaf hashes (the leaf hash of d(i) is MTH({d(i)})).
func rfcMTH(leaves []tlog.Hash) tlog.Hash {
	switch n := len(leaves); n {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	default:
		k := rfcSplit(n)
		return rfcNode(rfcMTH(leaves[:k]), rfcMTH(leaves[k:]))
	}
}

// RFC 9162 2.1.3.1 PATH(m, D[n]), bottom to top.
func rfcPath(m int, leaves []tlog.Hash) []tlog.Hash {
	n := len(leaves)
	if n <= 1 {
		return []tlog.Hash{}
	}
	k := rfcSplit(n)
	if m < k {
		return append(rfcPath(m, leaves[:k]), rfcMTH(leaves[k:]))
	}
	return append(rfcPath(m-k, leaves[k:]), rfcMTH(leaves[:k]))
}

// RFC 9162 2.1.3.2 verification algorithm, step by step.
func rfcVerify(index, size int64, leaf tlog.Hash, path []tlog.Hash, root tlog.Hash) bool {
	if index < 0 || size < 0 || index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = rfcNode(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = rfcNode(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && r == root
}

func tlogVerify(index, size int64, leaf tlog.Hash, path []tlog.Hash, root tlog.Hash) bool {
	return tlog.CheckRecord(tlog.RecordProof(path), size, root, index, leaf) == nil
}

// rfcVerifyCase is the RFC 9162 section 2.1.3.2 answer for a fixture case.
func rfcVerifyCase(c Inclusion) (bool, error) {
	leaf, err := parseHex(c.LeafHash)
	if err != nil {
		return false, err
	}
	root, err := parseHex(c.Root)
	if err != nil {
		return false, err
	}
	var p []tlog.Hash
	for _, s := range c.Path {
		h, err := parseHex(s)
		if err != nil {
			return false, err
		}
		p = append(p, h)
	}
	return rfcVerify(c.LeafIndex, c.TreeSize, leaf, p, root), nil
}

// rfcVariant is the RFC 9162 section 2.1.3.2 loop with checks switched off,
// used only to measure what each edge case tests. checkIndex is step 1 (fail
// when leaf_index >= tree_size); checkLength is the two path-length rules
// (fail when sn is 0 with path left, and require sn == 0 at the end). With
// both on it is rfcVerify.
func rfcVariant(index, size int64, leaf tlog.Hash, path []tlog.Hash, root tlog.Hash, checkIndex, checkLength bool) bool {
	if checkIndex && (index < 0 || size < 0 || index >= size) {
		return false
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if checkLength && sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = rfcNode(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = rfcNode(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if checkLength && sn != 0 {
		return false
	}
	return r == root
}

// rfcEndState runs the RFC 9162 section 2.1.3.2 loop over the whole path with
// no checks and returns fn and sn at the end.
func rfcEndState(index, size int64, pathLen int) (int64, int64) {
	fn, sn := index, size-1
	for i := 0; i < pathLen; i++ {
		if fn&1 == 0 && fn == sn {
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		}
		fn >>= 1
		sn >>= 1
	}
	return fn, sn
}

// bitsOnly is the classic index-bit fold that ignores tree_size and the path
// length: right child when the index bit is 1, left child otherwise.
func bitsOnly(index int64, leaf tlog.Hash, path []tlog.Hash, root tlog.Hash) bool {
	r := leaf
	for _, p := range path {
		if index&1 == 1 {
			r = rfcNode(p, r)
		} else {
			r = rfcNode(r, p)
		}
		index >>= 1
	}
	return r == root
}

// trapStats says, per edge kind, how many cases a verifier missing one rule
// would accept: those cases are rejected by that rule alone.
type trapStats struct {
	total, noIndex, noLength, bits map[edgeKind]int
	shortSubtree                   int // short paths tlog.CheckRecord accepts inside the named subtree
	shortRightEdge                 int // short paths after which the RFC loop has fn == sn != 0
	shortRightLeaf                 int // short cases whose leaf is in the right subtree of the top split
	nextSize                       int // long paths that are RFC-valid at tree_size n+1
}

func trapCounts(cases []Inclusion, meta []edgeMeta) trapStats {
	ts := trapStats{total: map[edgeKind]int{}, noIndex: map[edgeKind]int{}, noLength: map[edgeKind]int{}, bits: map[edgeKind]int{}}
	for i, c := range cases {
		mt := meta[i]
		leaf, _ := parseHex(c.LeafHash)
		root, _ := parseHex(c.Root)
		var p []tlog.Hash
		for _, s := range c.Path {
			h, _ := parseHex(s)
			p = append(p, h)
		}
		ts.total[mt.kind]++
		if rfcVariant(c.LeafIndex, c.TreeSize, leaf, p, root, false, true) {
			ts.noIndex[mt.kind]++
		}
		if rfcVariant(c.LeafIndex, c.TreeSize, leaf, p, root, true, false) {
			ts.noLength[mt.kind]++
		}
		if bitsOnly(c.LeafIndex, leaf, p, root) {
			ts.bits[mt.kind]++
		}
		switch mt.kind {
		case edgeShort:
			k := splitPoint(mt.n)
			size, idx := k, mt.m
			if mt.m >= k {
				size, idx = mt.n-k, mt.m-k
			}
			if tlogVerify(idx, size, leaf, p, root) {
				ts.shortSubtree++
			}
			if fn, sn := rfcEndState(c.LeafIndex, c.TreeSize, len(p)); fn == sn && sn != 0 {
				ts.shortRightEdge++
			}
			if mt.m >= k {
				ts.shortRightLeaf++
			}
		case edgeLongRight:
			if rfcVerify(mt.m, mt.n+1, leaf, p, root) {
				ts.nextSize++
			}
		}
	}
	return ts
}

// extraChecks compares tlog to the RFC reference over every fixture tree and
// inclusion case plus structural edge cases, confirms the published
// consistency proof and tree size 0 behavior, and measures the edge cases with
// the lenient verifier variants. It returns a summary for the OK line.
func extraChecks(c *checker, f *Fixture) string {
	n := 0
	agree := func(what string, index, size int64, leaf tlog.Hash, path []tlog.Hash, root tlog.Hash) {
		a := tlogVerify(index, size, leaf, path, root)
		b := rfcVerify(index, size, leaf, path, root)
		if a != b {
			c.fail("deviation: %s: tlog.CheckRecord=%v, RFC 9162 2.1.3.2=%v", what, a, b)
		}
		n++
	}

	for _, t := range f.Trees {
		var leaves []tlog.Hash
		for _, s := range t.LeafHashes {
			h, err := parseHex(s)
			if err != nil {
				return fmt.Sprintf("%d RFC 9162 reference checks (stopped at a bad leaf hash)", n)
			}
			leaves = append(leaves, h)
		}
		if int64(len(leaves)) != t.TreeSize {
			// verify reports the mismatch; walking a tree_size the leaves do
			// not back could run for as long as that number says.
			continue
		}
		root, _ := parseHex(t.Root)
		if rfcMTH(leaves) != root {
			c.fail("deviation: tree %q: RFC 9162 MTH differs from tlog.TreeHash", t.Name)
		}
		n++
		// Every index: RFC PATH == tlog.ProveRecord, and both verifiers agree
		// on the proof and on structural mutations of it.
		s, err := fromLeafHashes(leaves)
		if err != nil {
			c.fail("tree %q: %v", t.Name, err)
			continue
		}
		for m := int64(0); m < t.TreeSize; m++ {
			p, err := tlog.ProveRecord(t.TreeSize, m, s)
			if err != nil {
				c.fail("tree %q: ProveRecord(%d, %d): %v", t.Name, t.TreeSize, m, err)
				continue
			}
			rp := rfcPath(int(m), leaves)
			if !equalProof(p, rp) {
				c.fail("deviation: tree %q index %d: RFC 9162 PATH differs from tlog.ProveRecord", t.Name, m)
			}
			n++
			leaf := leaves[m]
			label := fmt.Sprintf("tree %q index %d", t.Name, m)
			agree(label+" proof", m, t.TreeSize, leaf, p, root)
			agree(label+" index = tree_size", t.TreeSize, t.TreeSize, leaf, p, root)
			agree(label+" tree_size + 1", m, t.TreeSize+1, leaf, p, root)
			agree(label+" extra trailing hash", m, t.TreeSize, leaf, append(append([]tlog.Hash{}, p...), root), root)
			if len(p) > 0 {
				agree(label+" last hash dropped", m, t.TreeSize, leaf, p[:len(p)-1], root)
				agree(label+" first hash dropped", m, t.TreeSize, leaf, p[1:], root)
				rev := make([]tlog.Hash, len(p))
				for i := range p {
					rev[i] = p[len(p)-1-i]
				}
				agree(label+" path reversed", m, t.TreeSize, leaf, rev, root)
			}
			if m^1 < t.TreeSize {
				agree(label+" sibling index", m^1, t.TreeSize, leaf, p, root)
			}
		}
	}

	// Every inclusion case: tlog against RFC 9162 section 2.1.3.2. A
	// disagreement is allowed only where the case records the RFC answer in
	// rfc9162_valid.
	var edgesInFile []Inclusion
	for _, in := range f.Inclusion {
		leaf, _ := parseHex(in.LeafHash)
		root, _ := parseHex(in.Root)
		var p []tlog.Hash
		for _, s := range in.Path {
			h, _ := parseHex(s)
			p = append(p, h)
		}
		if !tlogReturns(in.TreeSize, in.LeafIndex, len(p)) {
			continue // verify reports it
		}
		a := tlogVerify(in.LeafIndex, in.TreeSize, leaf, p, root)
		b := rfcVerify(in.LeafIndex, in.TreeSize, leaf, p, root)
		switch {
		case a != b && (in.RFC9162Valid == nil || *in.RFC9162Valid != b):
			c.fail("deviation: inclusion %q: tlog.CheckRecord=%v, RFC 9162 2.1.3.2=%v, and rfc9162_valid does not record it", in.Name, a, b)
		case a == b && in.RFC9162Valid != nil:
			c.fail("inclusion %q: rfc9162_valid is set, but tlog and RFC 9162 agree", in.Name)
		}
		if rfcVariant(in.LeafIndex, in.TreeSize, leaf, p, root, true, true) != b {
			c.fail("reference: rfcVariant with every check on differs from rfcVerify on %q", in.Name)
		}
		n++
		if strings.Contains(in.Name, edgeTag) {
			edgesInFile = append(edgesInFile, in)
		}
	}

	// Edge cases: what each one tests.
	summary := ""
	var seq []tlog.Hash
	for _, t := range f.Trees {
		if t.Name == testTreeName(testTreeMaxSize) {
			for _, s := range t.LeafHashes {
				h, _ := parseHex(s)
				seq = append(seq, h)
			}
		}
	}
	if _, meta, err := edgeCases(seq); err != nil || len(meta) != len(edgesInFile) {
		c.fail("edge cases: cannot pair the fixture's edge cases with their kinds (%v)", err)
	} else {
		ts := trapCounts(edgesInFile, meta)
		want := map[edgeKind]int{
			edgeIndexEqSize: testTreeProofMaxSize, edgeIndexMax: testTreeProofMaxSize,
			edgeIndexPlusPow: testTreeProofMaxSize * (testTreeProofMaxSize + 1) / 2,
			edgeShort:        testTreeProofMaxSize*(testTreeProofMaxSize+1)/2 - 1,
			edgeLongLeft:     testTreeProofMaxSize * (testTreeProofMaxSize + 1) / 2,
			edgeLongRight:    testTreeProofMaxSize * (testTreeProofMaxSize + 1) / 2,
			edgeSizeZero:     4,
		}
		for k, w := range want {
			if ts.total[k] != w {
				c.fail("edge cases: %d of kind %q, want %d", ts.total[k], k, w)
			}
		}
		for _, in := range edgesInFile {
			if in.Valid {
				c.fail("edge case %q: tlog.CheckRecord accepts it", in.Name)
			}
		}
		if ts.noLength[edgeShort] != ts.total[edgeShort] || ts.noLength[edgeLongLeft] != ts.total[edgeLongLeft] {
			c.fail("edge cases: only %d/%d short and %d/%d long-left paths pass the RFC loop without its length rules",
				ts.noLength[edgeShort], ts.total[edgeShort], ts.noLength[edgeLongLeft], ts.total[edgeLongLeft])
		}
		if ts.shortRightEdge != ts.shortRightLeaf {
			c.fail("edge cases: %d shortened paths end with fn == sn != 0, but %d have the leaf in the right subtree", ts.shortRightEdge, ts.shortRightLeaf)
		}
		if ts.shortSubtree != ts.total[edgeShort] {
			c.fail("edge cases: tlog.CheckRecord accepts only %d/%d shortened paths as proofs inside their subtree", ts.shortSubtree, ts.total[edgeShort])
		}
		understated := 0
		for _, in := range edgesInFile {
			if strings.Contains(in.Name, "tree_size understated") {
				understated++
			}
		}
		if ts.nextSize != understated {
			c.fail("edge cases: %d long-right paths are RFC-valid at tree_size n+1, %d are named so", ts.nextSize, understated)
		}
		summary = fmt.Sprintf("edge cases rejected by one rule alone: %d/%d short and %d/%d long paths by the length rule, %d/%d index cases by the index rule",
			ts.noLength[edgeShort], ts.total[edgeShort], ts.noLength[edgeLongLeft], ts.total[edgeLongLeft],
			ts.noIndex[edgeIndexEqSize]+ts.noIndex[edgeIndexPlusPow]+ts.noIndex[edgeIndexMax],
			ts.total[edgeIndexEqSize]+ts.total[edgeIndexPlusPow]+ts.total[edgeIndexMax])
	}

	// The full upstream TestTree range, sizes 1..100 built incrementally as
	// tlog_test.go:65-77 does: TreeHash vs MTH, ProveRecord vs PATH, and
	// verifier agreement on each proof and each upstream corruption of it.
	var st storage
	var leaves []tlog.Hash
	for i := int64(0); i < testTreeMaxSize; i++ {
		data := fmt.Appendf(nil, testTreeLeafFormat, i)
		hs, err := tlog.StoredHashes(i, data, st)
		if err != nil {
			c.fail("TestTree range: StoredHashes(%d): %v", i, err)
			return fmt.Sprintf("%d RFC 9162 reference checks", n)
		}
		st = append(st, hs...)
		leaves = append(leaves, tlog.RecordHash(data))
		size := i + 1
		th, err := tlog.TreeHash(size, st)
		if err != nil || th != rfcMTH(leaves) {
			c.fail("deviation: TestTree range size %d: tlog.TreeHash differs from RFC 9162 MTH", size)
		}
		n++
		for m := int64(0); m < size; m++ {
			p, err := tlog.ProveRecord(size, m, st)
			if err != nil || !equalProof(p, rfcPath(int(m), leaves)) {
				c.fail("deviation: TestTree range size %d index %d: tlog.ProveRecord differs from RFC 9162 PATH", size, m)
				continue
			}
			n++
			label := fmt.Sprintf("TestTree range size %d index %d", size, m)
			agree(label, m, size, leaves[m], p, th)
			if !tlogVerify(m, size, leaves[m], p, th) {
				c.fail("%s: CheckRecord rejects ProveRecord's proof", label)
			}
			for k := range p {
				q := append(tlog.RecordProof{}, p...)
				q[k][0] ^= 1
				agree(fmt.Sprintf("%s path element %d with a flipped bit", label, k), m, size, leaves[m], q, th)
				if tlogVerify(m, size, leaves[m], q, th) {
					c.fail("%s: CheckRecord accepts path element %d with a flipped bit", label, k)
				}
			}
		}
	}

	// Tree size 0.
	if h, err := tlog.TreeHash(0, nil); err != nil || h != tlog.Hash(sha256.Sum256(nil)) {
		c.fail("TreeHash(0, nil) = %s, %v; want SHA-256(\"\")", hx(h), err)
	}
	n++
	if _, err := tlog.ProveRecord(0, 0, storage{}); err == nil {
		c.fail("ProveRecord(t=0, n=0) succeeded, want an error")
	}
	n++
	empty := tlog.Hash(sha256.Sum256(nil))
	if tlog.CheckRecord(tlog.RecordProof{}, 0, empty, 0, empty) == nil {
		c.fail("CheckRecord(t=0) accepted a proof")
	}
	n++

	// Published consistency proof, sumdb/client_test.go:135-138.
	tc2 := [][]byte{[]byte(clientRecord0), []byte(clientRecord1), []byte(clientRecord2), []byte(clientRecord3), []byte(tc2Record4), []byte(tc2Record5)}
	s, err := fromLeafData(tc2)
	if err != nil {
		c.fail("tc2 storage: %v", err)
		return fmt.Sprintf("%d RFC 9162 reference checks", n)
	}
	pub := tlog.TreeProof{mustB64(forkProof0B64), mustB64(forkProof1B64), mustB64(forkProof2B64)}
	tp, err := tlog.ProveTree(6, 5, s)
	if err != nil || len(tp) != len(pub) {
		c.fail("ProveTree(6, 5) over tc2 = %v, %v; want the published proof", tp, err)
	} else {
		for i := range tp {
			if tp[i] != pub[i] {
				c.fail("ProveTree(6, 5)[%d] = %v, published %v", i, tp[i], pub[i])
			}
		}
	}
	n++
	if err := tlog.CheckTree(pub, 6, mustB64(forkNewTree6RootB64), 5, mustB64(forkTc2Tree5RootB64)); err != nil {
		c.fail("CheckTree(published proof, 6, tc2 root 6, 5, tc2 root 5): %v", err)
	}
	n++
	if tlog.CheckTree(pub, 6, mustB64(forkNewTree6RootB64), 5, mustB64(forkOldTree5RootB64)) == nil {
		c.fail("CheckTree accepted tc's forked tree 5 inside tc2's tree 6")
	}
	n++
	return fmt.Sprintf("%d RFC 9162 reference checks, %s", n, summary)
}
