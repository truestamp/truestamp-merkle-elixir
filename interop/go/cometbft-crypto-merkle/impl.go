// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains code adapted from github.com/cometbft/cometbft@v1.0.1 (Apache-2.0):
// crypto/merkle/proof.go:79-114 (Proof.Verify) and crypto/merkle/tree.go:15-27
// (hashFromByteSlices). License text: LICENSE-cometbft. See NOTICE.

package main

// Access to the implementation's own unexported functions.
//
// crypto/merkle exports HashFromByteSlices, HashFromByteSlicesIterative,
// ProofsFromByteSlices and Proof.Verify(root, leafDATA). Verify takes leaf data,
// not a leaf hash: it checks root != nil, Total >= 0, Index >= 0, that
// Proof.LeafHash == SHA-256(0x00 || leaf), then calls the unexported
// computeHashFromAunts (proof.go:206-237) and compares the result with root
// (proof.go:79-114). Our cross-check works at the leaf-hash level, so the
// verifier core and the hash primitives are reached with go:linkname (pull
// linknames into non-standard-library packages are permitted; linkname.s lets
// the bodyless declarations compile). Every case whose leaf data is known is
// ALSO run through the exported Proof.Verify and must give the same answer.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"hash"
	_ "unsafe" // go:linkname
)

//go:linkname cmtComputeHashFromAunts github.com/cometbft/cometbft/crypto/merkle.computeHashFromAunts
func cmtComputeHashFromAunts(h hash.Hash, index, total int64, leafHash []byte, innerHashes [][]byte) ([]byte, error)

//go:linkname cmtInnerHash github.com/cometbft/cometbft/crypto/merkle.innerHash
func cmtInnerHash(left []byte, right []byte) []byte

//go:linkname cmtLeafHash github.com/cometbft/cometbft/crypto/merkle.leafHash
func cmtLeafHash(leaf []byte) []byte

//go:linkname cmtEmptyHash github.com/cometbft/cometbft/crypto/merkle.emptyHash
func cmtEmptyHash() []byte

//go:linkname cmtGetSplitPoint github.com/cometbft/cometbft/crypto/merkle.getSplitPoint
func cmtGetSplitPoint(length int64) int64

// implVerifyLeafHash is Proof.Verify (github.com/cometbft/cometbft v1.0.1
// crypto/merkle/proof.go:79-114, Apache-2.0) with the leaf-data step removed:
// same nil-root check, same negative checks, same core, same compare.
func implVerifyLeafHash(leafHash []byte, index, total int64, aunts [][]byte, root []byte) (bool, error) {
	if root == nil {
		return false, errors.New("nil root")
	}
	if total < 0 {
		return false, errors.New("negative proof total")
	}
	if index < 0 {
		return false, errors.New("negative proof index")
	}
	computed, err := cmtComputeHashFromAunts(sha256.New(), index, total, leafHash, aunts)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(computed, root) {
		return false, errors.New("root mismatch")
	}
	return true, nil
}

// implRootFromLeafHashes is hashFromByteSlices (github.com/cometbft/cometbft
// v1.0.1 crypto/merkle/tree.go:15-27, Apache-2.0) with the leaf step lifted:
// the same recursion over the implementation's own emptyHash, getSplitPoint and
// innerHash, starting from leaf hashes. It is used only to re-check trees whose
// leaf data is not written to the fixture (leaf_data null).
func implRootFromLeafHashes(lh [][]byte) []byte {
	switch len(lh) {
	case 0:
		return cmtEmptyHash()
	case 1:
		return lh[0]
	default:
		k := cmtGetSplitPoint(int64(len(lh)))
		left := implRootFromLeafHashes(lh[:k])
		right := implRootFromLeafHashes(lh[k:])
		return cmtInnerHash(left, right)
	}
}
