// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// An RFC 9162 section 2.1 reference written from the RFC text alone, with no
// code from the module under test. It decides "rfc9162_valid" and
// cross-checks that the module's published roots and paths are RFC 9162
// values. It never decides "valid" (that is the module's verdict) and never
// produces a published value.

import (
	"bytes"
	"crypto/sha256"
	"math/bits"
)

func refLeaf(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, data...))
	return h[:]
}

func refNode(l, r []byte) []byte {
	b := make([]byte, 0, 1+len(l)+len(r))
	b = append(b, 0x01)
	b = append(b, l...)
	b = append(b, r...)
	h := sha256.Sum256(b)
	return h[:]
}

// refSplit is k, the largest power of two smaller than n (n >= 2).
func refSplit(n uint64) uint64 { return uint64(1) << (bits.Len64(n-1) - 1) }

// refMTH is MTH(D[n]) over leaf hashes (section 2.1.1).
func refMTH(lh [][]byte) []byte {
	switch len(lh) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		return lh[0]
	}
	k := refSplit(uint64(len(lh)))
	return refNode(refMTH(lh[:k]), refMTH(lh[k:]))
}

// refPath is PATH(m, D[n]) over leaf hashes, bottom to top (section 2.1.3.1).
func refPath(m uint64, lh [][]byte) [][]byte {
	n := uint64(len(lh))
	if n <= 1 {
		return [][]byte{}
	}
	k := refSplit(n)
	if m < k {
		return append(refPath(m, lh[:k]), refMTH(lh[k:]))
	}
	return append(refPath(m-k, lh[k:]), refMTH(lh[:k]))
}

// refRanges returns the subtree ranges [lo, hi) of the PATH(m, D[n])
// recursion from the whole tree (depth 0) down to the leaf (depth
// len(PATH)). After a verifier has consumed the first j elements of the path,
// the value it holds is the hash of ranges[len(PATH)-j].
func refRanges(m, n uint64) [][2]uint64 {
	lo, hi := uint64(0), n
	out := [][2]uint64{{lo, hi}}
	for hi-lo > 1 {
		k := refSplit(hi - lo)
		if m-lo < k {
			hi = lo + k
		} else {
			lo = lo + k
		}
		out = append(out, [2]uint64{lo, hi})
	}
	return out
}

// refVerify is the section 2.1.3.2 algorithm, step by step.
func refVerify(leafHash []byte, leafIndex, treeSize uint64, path [][]byte, root []byte) bool {
	// 1. leaf_index >= tree_size fails.
	if leafIndex >= treeSize {
		return false
	}
	// 2. fn = leaf_index, sn = tree_size - 1.  3. r = hash.
	fn, sn := leafIndex, treeSize-1
	r := leafHash
	// 4. For each p in inclusion_path:
	for _, p := range path {
		// a. sn == 0: stop and fail.
		if sn == 0 {
			return false
		}
		// b.
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
		// c.
		fn >>= 1
		sn >>= 1
	}
	// 5. sn == 0 and r == root_hash.
	return sn == 0 && bytes.Equal(r, root)
}

// refChainUnchecked runs step 4 of section 2.1.3.2 over the whole path with
// none of the section's failure checks (no step 1 index check, no step 4a
// stop at sn == 0, no step 5 sn == 0 requirement) and returns r: the root a
// verifier that skipped those checks would compare against. A refusal case
// of the library's vectors offers it as the root, so that a verifier under
// test can refuse only by checking the index or the path length. treeSize
// must be at least 1.
func refChainUnchecked(leafHash []byte, leafIndex, treeSize uint64, path [][]byte) []byte {
	fn, sn := leafIndex, treeSize-1
	r := leafHash
	for _, p := range path {
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
		fn >>= 1
		sn >>= 1
	}
	return r
}
