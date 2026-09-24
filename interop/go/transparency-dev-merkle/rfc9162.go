// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
)

// LeafDataRule is the fixture schema's leaf_data_rule: leaf i, for i from
// First to First+tree_size-1, has data = the encoding of i. Only "u16le" is
// used in this file: 2 bytes, little-endian ([i & 0xff, (i >> 8) & 0xff]),
// defined for i <= 65535.
type LeafDataRule struct {
	Encoding string `json:"encoding"`
	First    uint64 `json:"first"`
}

// ruleLeafData returns the data of leaf i under the rule (i is the absolute
// index, First <= i).
func ruleLeafData(r *LeafDataRule, i uint64) ([]byte, error) {
	switch r.Encoding {
	case "u16le":
		if i > 0xffff {
			return nil, fmt.Errorf("u16le: index %d does not fit in 2 bytes", i)
		}
		return []byte{byte(i), byte(i >> 8)}, nil
	default:
		return nil, fmt.Errorf("unknown leaf_data_rule encoding %q", r.Encoding)
	}
}

// rfc9162Verify is RFC 9162 section 2.1.3.2 transcribed step by step on
// indepHasher (crypto/sha256), with no code from the implementation under
// test. typed=true first requires the leaf hash, the root and every path
// element to be SHA-256 outputs (32 bytes): the algorithm verifies a "hash"
// against a "root_hash", both outputs of HASH, and an inclusion path is a
// list of node hashes. typed=false runs the bare algorithm on whatever bytes
// it is given, which is how the one malformed-length case in this file is
// reported in the notes.
func rfc9162Verify(leafHash []byte, leafIndex, treeSize uint64, path [][]byte, rootHash []byte, typed bool) bool {
	if typed {
		if len(leafHash) != 32 || len(rootHash) != 32 {
			return false
		}
		for _, p := range path {
			if len(p) != 32 {
				return false
			}
		}
	}
	// 1. leaf_index >= tree_size fails.
	if leafIndex >= treeSize {
		return false
	}
	// 2. fn = leaf_index, sn = tree_size - 1. 3. r = hash.
	fn, sn := leafIndex, treeSize-1
	r := leafHash
	// 4. For each p in inclusion_path:
	for _, p := range path {
		// a. sn == 0: stop and fail.
		if sn == 0 {
			return false
		}
		// b. LSB(fn) set, or fn == sn:
		if fn&1 == 1 || fn == sn {
			// i. r = HASH(0x01 || p || r)
			r = ih.HashChildren(p, r)
			// ii. If LSB(fn) is not set, right-shift fn and sn equally until
			// either LSB(fn) is set or fn is 0.
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			// Otherwise r = HASH(0x01 || r || p).
			r = ih.HashChildren(r, p)
		}
		// c. Right-shift fn and sn once.
		fn >>= 1
		sn >>= 1
	}
	// 5. sn == 0 and r == root_hash.
	return sn == 0 && bytes.Equal(r, rootHash)
}
