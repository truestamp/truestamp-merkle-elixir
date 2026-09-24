// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
// Contains the TestTree leaf data format "leaf %d" quoted from
// golang.org/x/mod@v0.41.0 (sumdb/tlog/tlog_test.go:66) in case names,
// BSD-3-Clause, Copyright 2009 The Go Authors; see LICENSE-golang-x-mod and
// NOTICE.

package main

// Edge cases that upstream TestTree never asks about: a leaf index at or past
// the tree size, a tree of size 0, and audit paths one element too short or
// too long. They are built over the upstream TestTree leaf data "leaf %d"
// (sumdb/tlog/tlog_test.go:65-66) for tree sizes 1..testTreeProofMaxSize, and
// every value in them comes from tlog's own functions: StoredHashesForRecordHash,
// TreeHash, ProveRecord and NodeHash build the leaf hash, path and root, and
// CheckRecord gives the verdict.
//
// edgeCases takes the TestTree leaf hashes in order (seq[i] = RecordHash("leaf
// i")). generate() passes hashes it computes from the upstream format string;
// verify() passes the leaf_hashes of the fixture's own size 100 TestTree tree,
// so the check re-derives every case from the file with tlog alone.

import (
	"fmt"
	"math"

	"golang.org/x/mod/sumdb/tlog"
)

const edgeTag = `edge "`

type edgeKind string

const (
	edgeIndexEqSize  edgeKind = "index = tree_size"
	edgeIndexPlusPow edgeKind = "index >= tree_size, low bits kept"
	edgeIndexMax     edgeKind = "index >= tree_size, int64 max"
	edgeShort        edgeKind = "path one short"
	edgeLongLeft     edgeKind = "path one long, extra hash folded on the left"
	edgeLongRight    edgeKind = "path one long, extra hash folded on the right"
	edgeSizeZero     edgeKind = "tree_size 0"
)

type edgeMeta struct {
	kind edgeKind
	n, m int64 // base TestTree size and the leaf whose proof the case starts from
}

// smallest power of two >= n (n >= 1)
func pow2AtLeast(n int64) (int64, int) {
	p, bits := int64(1), 0
	for p < n {
		p <<= 1
		bits++
	}
	return p, bits
}

func edgeCases(seq []tlog.Hash) ([]Inclusion, []edgeMeta, error) {
	maxN := int64(testTreeProofMaxSize)
	if int64(len(seq)) < maxN+1 {
		return nil, nil, fmt.Errorf("edge cases need %d TestTree leaf hashes, have %d", maxN+1, len(seq))
	}
	type base struct {
		s     storage
		root  tlog.Hash
		paths []tlog.RecordProof
	}
	bases := map[int64]base{}
	for n := int64(1); n <= maxN+1; n++ {
		s, err := fromLeafHashes(seq[:n])
		if err != nil {
			return nil, nil, err
		}
		root, err := tlog.TreeHash(n, s)
		if err != nil {
			return nil, nil, err
		}
		b := base{s: s, root: root}
		for m := int64(0); m < n; m++ {
			p, err := tlog.ProveRecord(n, m, s)
			if err != nil {
				return nil, nil, fmt.Errorf("ProveRecord(%d, %d): %v", n, m, err)
			}
			b.paths = append(b.paths, p)
		}
		bases[n] = b
	}

	var out []Inclusion
	var meta []edgeMeta
	add := func(k edgeKind, n, m int64, name string, leaf tlog.Hash, index, size int64, p tlog.RecordProof, root tlog.Hash) {
		out = append(out, Inclusion{
			Name:                "generated: " + edgeTag + string(k) + `": ` + name,
			LeafHash:            hx(leaf),
			LeafIndex:           index,
			TreeSize:            size,
			Path:                pathHex(p),
			Root:                hx(root),
			Valid:               tlog.CheckRecord(p, size, root, index, leaf) == nil,
			UpstreamExpectation: "none",
		})
		meta = append(meta, edgeMeta{kind: k, n: n, m: m})
	}
	tt := func(n int64) string { return fmt.Sprintf(`TestTree "leaf %%d" tree_size %d`, n) }

	// index = tree_size: the last leaf's own proof and root, index moved one past it.
	for n := int64(1); n <= maxN; n++ {
		b, m := bases[n], n-1
		add(edgeIndexEqSize, n, m,
			fmt.Sprintf("%s, leaf %d hash with ProveRecord(%d, %d) path and TreeHash(%d) root, leaf_index set to %d", tt(n), m, n, m, n, n),
			seq[m], n, n, b.paths[m], b.root)
	}
	// index past the tree with the same low bits: m + 2^K, 2^K the smallest power of two >= n.
	for n := int64(1); n <= maxN; n++ {
		b := bases[n]
		pw, bits := pow2AtLeast(n)
		for m := int64(0); m < n; m++ {
			add(edgeIndexPlusPow, n, m,
				fmt.Sprintf("%s, leaf %d hash with ProveRecord(%d, %d) path and TreeHash(%d) root, leaf_index set to %d + %d = %d (same low %d bits)", tt(n), m, n, m, n, m, pw, m+pw, bits),
				seq[m], m+pw, n, b.paths[m], b.root)
		}
	}
	// index = the largest int64, the last leaf's proof and root.
	for n := int64(1); n <= maxN; n++ {
		b, m := bases[n], n-1
		add(edgeIndexMax, n, m,
			fmt.Sprintf("%s, leaf %d hash with ProveRecord(%d, %d) path and TreeHash(%d) root, leaf_index set to %d (2^63 - 1)", tt(n), m, n, m, n, int64(math.MaxInt64)),
			seq[m], math.MaxInt64, n, b.paths[m], b.root)
	}
	// path one short: drop the top element. What is left is exactly the proof of
	// leaf m inside the child subtree of the top split, so the root is that
	// subtree's hash, computed with tlog.TreeHash.
	for n := int64(2); n <= maxN; n++ {
		b := bases[n]
		k := splitPoint(n)
		for m := int64(0); m < n; m++ {
			p := b.paths[m]
			short := append(tlog.RecordProof{}, p[:len(p)-1]...)
			var sub tlog.Hash
			var desc string
			if m < k {
				h, err := tlog.TreeHash(k, b.s)
				if err != nil {
					return nil, nil, err
				}
				sub = h
				desc = fmt.Sprintf("TreeHash(%d), the subtree D[0:%d]", k, k)
			} else {
				ss, err := fromLeafHashes(seq[k:n])
				if err != nil {
					return nil, nil, err
				}
				h, err := tlog.TreeHash(n-k, ss)
				if err != nil {
					return nil, nil, err
				}
				sub = h
				desc = fmt.Sprintf("TreeHash(%d) over leaves %d..%d, the subtree D[%d:%d]", n-k, k, n-1, k, n)
			}
			add(edgeShort, n, m,
				fmt.Sprintf("%s leaf_index %d, ProveRecord(%d, %d) with its last (top) element dropped; root %s that the shortened path proves leaf %d in", tt(n), m, n, m, desc, m),
				seq[m], m, n, short, sub)
		}
	}
	// path one long: one extra hash on top. The extra hash is the next TestTree
	// leaf hash, RecordHash("leaf n").
	for _, left := range []bool{true, false} {
		for n := int64(1); n <= maxN; n++ {
			b := bases[n]
			x := seq[n]
			for m := int64(0); m < n; m++ {
				long := append(append(tlog.RecordProof{}, b.paths[m]...), x)
				if left {
					add(edgeLongLeft, n, m,
						fmt.Sprintf(`%s leaf_index %d, ProveRecord(%d, %d) plus RecordHash("leaf %d") appended on top; root NodeHash(RecordHash("leaf %d"), TreeHash(%d))`, tt(n), m, n, m, n, n, n),
						seq[m], m, n, long, tlog.NodeHash(x, b.root))
					continue
				}
				root := tlog.NodeHash(b.root, x)
				extra := ""
				nb := bases[n+1]
				if root == nb.root && equalProof(long, nb.paths[m]) {
					extra = fmt.Sprintf(" (equal to TreeHash(%d) and ProveRecord(%d, %d): the size %d proof with tree_size understated)", n+1, n+1, m, n+1)
				}
				add(edgeLongRight, n, m,
					fmt.Sprintf(`%s leaf_index %d, ProveRecord(%d, %d) plus RecordHash("leaf %d") appended on top; root NodeHash(TreeHash(%d), RecordHash("leaf %d"))%s`, tt(n), m, n, m, n, n, n, extra),
					seq[m], m, n, long, root)
			}
		}
	}
	// tree_size 0. TreeHash(0, nil) is the empty hash.
	empty, err := tlog.TreeHash(0, nil)
	if err != nil {
		return nil, nil, err
	}
	b1, b2 := bases[1], bases[2]
	add(edgeSizeZero, 0, 0, "leaf_index 0, empty path, leaf_hash and root both TreeHash(0) = SHA-256(\"\")",
		empty, 0, 0, tlog.RecordProof{}, empty)
	add(edgeSizeZero, 0, 0, `leaf_index 0, empty path, leaf_hash RecordHash("leaf 0") and root TreeHash(1) of TestTree (the same hash)`,
		seq[0], 0, 0, tlog.RecordProof{}, b1.root)
	add(edgeSizeZero, 0, 0, `leaf_index 0, empty path, leaf_hash RecordHash("leaf 0"), root TreeHash(0) = SHA-256("")`,
		seq[0], 0, 0, tlog.RecordProof{}, empty)
	add(edgeSizeZero, 0, 0, `leaf_index 0, leaf_hash RecordHash("leaf 0") with the TestTree tree_size 2 proof ProveRecord(2, 0) and root TreeHash(2), tree_size set to 0`,
		seq[0], 0, 0, b2.paths[0], b2.root)
	return out, meta, nil
}

// splitPoint is the k of RFC 9162 section 2.1.1: the largest power of two
// strictly smaller than n (n >= 2).
func splitPoint(n int64) int64 {
	k := int64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}
