// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// An RFC 9162 section 2.1 reference written from the RFC text alone. It shares
// no code with any upstream module, so every value in the fixture is checked
// twice: once by transparency-dev/merkle v0.0.2 and once by this file.

import (
	"bytes"
	"crypto/sha256"
	"math/bits"
)

// refLeaf is MTH({d(0)}) = SHA-256(0x00 || d(0)) (RFC 9162 section 2.1.1).
func refLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// refNode is SHA-256(0x01 || left || right) (RFC 9162 section 2.1.1).
func refNode(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// refEmpty is MTH({}) = SHA-256() (RFC 9162 section 2.1.1).
func refEmpty() []byte {
	h := sha256.Sum256(nil)
	return h[:]
}

// refSplit returns k, the largest power of two smaller than n (n >= 2).
func refSplit(n uint64) uint64 {
	return uint64(1) << (bits.Len64(n-1) - 1)
}

// refMTH is the Merkle Tree Hash over leaf hashes (RFC 9162 section 2.1.1).
func refMTH(lh [][]byte) []byte {
	switch n := uint64(len(lh)); n {
	case 0:
		return refEmpty()
	case 1:
		return lh[0]
	default:
		k := refSplit(n)
		return refNode(refMTH(lh[:k]), refMTH(lh[k:]))
	}
}

// refPath is PATH(m, D[n]) over leaf hashes, bottom to top (RFC 9162 section 2.1.3.1).
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

// refRun runs the loop of RFC 9162 section 2.1.3.2 over path and reports r, sn
// and whether the loop failed early (sn reached 0 with path elements left).
func refRun(leaf []byte, m, n uint64, path [][]byte) (r []byte, sn uint64, ok bool) {
	if m >= n {
		return nil, 0, false
	}
	fn := m
	sn = n - 1
	r = leaf
	for _, p := range path {
		if sn == 0 {
			return r, sn, false
		}
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
	return r, sn, true
}

// refVerify is RFC 9162 section 2.1.3.2 verbatim.
func refVerify(leaf []byte, m, n uint64, path [][]byte, root []byte) bool {
	r, sn, ok := refRun(leaf, m, n, path)
	return ok && sn == 0 && bytes.Equal(r, root)
}

// refSiblingLeft gives, for PATH(m, D[n]) bottom to top, whether each element
// is a left sibling (combined as SHA-256(0x01 || p || r)).
func refSiblingLeft(m, n uint64) []bool {
	var d []bool
	if m >= n {
		return nil
	}
	fn, sn := m, n-1
	for sn != 0 {
		if fn&1 == 1 || fn == sn {
			d = append(d, true)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			d = append(d, false)
		}
		fn >>= 1
		sn >>= 1
	}
	return d
}

// refIndexFromSides finds the unique leaf index m < n whose RFC 9162 path has
// exactly the given sibling sides (bottom to top), walking the RFC 9162 split
// from the top. ok is false when no index of a tree of size n fits.
func refIndexFromSides(n uint64, siblingLeft []bool) (uint64, bool) {
	if n == 0 {
		return 0, false
	}
	off, size := uint64(0), n
	for i := len(siblingLeft) - 1; i >= 0; i-- {
		if size <= 1 {
			return 0, false
		}
		k := refSplit(size)
		if siblingLeft[i] {
			off += k
			size -= k
		} else {
			size = k
		}
	}
	if size != 1 {
		return 0, false
	}
	return off, true
}
