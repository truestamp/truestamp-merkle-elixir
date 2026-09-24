// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// An independent RFC 9162 section 2.1 reference, written from the RFC text
// with crypto/sha256 only. It shares no code with sigsum-go. The program uses
// it to show that every verdict in the fixture file is also the RFC 9162
// section 2.1.3.2 verdict (so no case needs "rfc9162_valid"), and that
// sigsum's roots and audit paths are RFC 9162 MTH and PATH.

import "crypto/sha256"

type h32 = [32]byte

// refLeaf is RFC 9162 2.1.1 MTH({d(0)}) = SHA-256(0x00 || d(0)).
func refLeaf(data []byte) h32 {
	b := make([]byte, 0, 1+len(data))
	b = append(b, 0x00)
	b = append(b, data...)
	return sha256.Sum256(b)
}

// refNode is SHA-256(0x01 || left || right).
func refNode(l, r h32) h32 {
	b := make([]byte, 0, 65)
	b = append(b, 0x01)
	b = append(b, l[:]...)
	b = append(b, r[:]...)
	return sha256.Sum256(b)
}

// refSplit is the largest power of two smaller than n, for n >= 2.
func refSplit(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// refMTH is RFC 9162 2.1.1 MTH over leaf hashes; the empty tree is SHA-256("").
func refMTH(leaves []h32) h32 {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	k := refSplit(len(leaves))
	return refNode(refMTH(leaves[:k]), refMTH(leaves[k:]))
}

// refPath is RFC 9162 2.1.3.1 PATH(m, D[n]), bottom to top.
func refPath(m int, leaves []h32) []h32 {
	if len(leaves) <= 1 {
		return []h32{}
	}
	k := refSplit(len(leaves))
	if m < k {
		return append(refPath(m, leaves[:k]), refMTH(leaves[k:]))
	}
	return append(refPath(m-k, leaves[k:]), refMTH(leaves[:k]))
}

// refVerify is RFC 9162 2.1.3.2, step by step.
func refVerify(leaf h32, index, size uint64, root h32, path []h32) bool {
	// 1. leaf_index >= tree_size fails.
	if index >= size {
		return false
	}
	// 2, 3.
	fn, sn := index, size-1
	r := leaf
	// 4.
	for _, p := range path {
		// 4a.
		if sn == 0 {
			return false
		}
		// 4b.
		if fn&1 == 1 || fn == sn {
			r = refNode(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = refNode(r, p)
		}
		// 4c.
		fn >>= 1
		sn >>= 1
	}
	// 5.
	return sn == 0 && r == root
}
