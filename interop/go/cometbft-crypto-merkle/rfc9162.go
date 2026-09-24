// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// An independent RFC 9162 section 2.1 reference, written from the RFC text and
// used only to judge conformance. It never produces a fixture value: every value
// in the fixture file comes from an upstream literal or from the implementation.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
)

// rfcLeafHash: MTH({d(0)}) = HASH(0x00 || d(0)).
func rfcLeafHash(d []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, d...))
	return h[:]
}

// rfcNodeHash: HASH(0x01 || left || right).
func rfcNodeHash(l, r []byte) []byte {
	buf := make([]byte, 0, 1+len(l)+len(r))
	buf = append(buf, 0x01)
	buf = append(buf, l...)
	buf = append(buf, r...)
	h := sha256.Sum256(buf)
	return h[:]
}

// rfcEmptyRoot: MTH({}) = HASH().
func rfcEmptyRoot() []byte {
	h := sha256.Sum256(nil)
	return h[:]
}

// rfcSplit: the largest power of two smaller than n (n > 1).
func rfcSplit(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// rfcMTHFromLeafHashes computes MTH over already-hashed leaves.
func rfcMTHFromLeafHashes(lh [][]byte) []byte {
	switch len(lh) {
	case 0:
		return rfcEmptyRoot()
	case 1:
		return lh[0]
	}
	k := rfcSplit(len(lh))
	return rfcNodeHash(rfcMTHFromLeafHashes(lh[:k]), rfcMTHFromLeafHashes(lh[k:]))
}

// rfcPath is PATH(m, D[n]) from RFC 9162 section 2.1.3.1, bottom to top.
func rfcPath(m int, lh [][]byte) [][]byte {
	n := len(lh)
	if n <= 1 {
		return [][]byte{}
	}
	k := rfcSplit(n)
	if m < k {
		return append(rfcPath(m, lh[:k]), rfcMTHFromLeafHashes(lh[k:]))
	}
	return append(rfcPath(m-k, lh[k:]), rfcMTHFromLeafHashes(lh[:k]))
}

// rfcVerify is the RFC 9162 section 2.1.3.2 verification algorithm. The RFC
// indices are unsigned; a negative value cannot be expressed and is rejected.
func rfcVerify(leafIndex, treeSize int64, leafHash []byte, path [][]byte, root []byte) bool {
	if leafIndex < 0 || treeSize < 0 {
		return false
	}
	// 1. If leaf_index >= tree_size, fail.
	if leafIndex >= treeSize {
		return false
	}
	// 2. fn = leaf_index, sn = tree_size - 1.
	fn, sn := uint64(leafIndex), uint64(treeSize-1)
	// 3. r = hash.
	r := leafHash
	// 4. For each p in inclusion_path.
	for _, p := range path {
		// a. If sn is 0, fail.
		if sn == 0 {
			return false
		}
		// b. If LSB(fn) is set, or if fn is equal to sn.
		if fn&1 == 1 || fn == sn {
			r = rfcNodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = rfcNodeHash(r, p)
		}
		// c. Right-shift fn and sn once.
		fn >>= 1
		sn >>= 1
	}
	// 5. sn must be 0 and r must equal root_hash.
	return sn == 0 && bytes.Equal(r, root)
}

// rfcSHA256 is plain SHA-256, used only to confirm that a leaf datum is the
// SHA-256 of an upstream literal.
func rfcSHA256(d []byte) []byte {
	h := sha256.Sum256(d)
	return h[:]
}

// rfcFnSnTrace replays only the index bookkeeping of the section 2.1.3.2 loop
// (steps 2, 4a, 4b and 4c, no hashing) for a path of pathLen elements and
// returns the (fn, sn) pair before each step and after the last one, as
// "fn,sn -> fn,sn -> ...". ok is false if step 4a would fail.
func rfcFnSnTrace(leafIndex, treeSize uint64, pathLen int) (trace string, ok bool) {
	fn, sn := leafIndex, treeSize-1
	parts := []string{fmt.Sprintf("%d,%d", fn, sn)}
	for i := 0; i < pathLen; i++ {
		if sn == 0 {
			return strings.Join(parts, " -> "), false
		}
		if fn&1 == 1 || fn == sn {
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		}
		fn >>= 1
		sn >>= 1
		parts = append(parts, fmt.Sprintf("%d,%d", fn, sn))
	}
	return strings.Join(parts, " -> "), true
}
