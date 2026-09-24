// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains code and literals copied from
// github.com/transparency-dev/merkle@v0.0.3-0.20260921095310-fbbcd741c3d1
// (main branch, commit fbbcd741c3d1, untagged; Apache-2.0, Copyright Google
// LLC): testonly/vectors_test.go and testonly/tree.go. The upstream license
// is vendored as LICENSE-transparency-dev-merkle; see NOTICE.

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/bits"
)

// ---------------------------------------------------------------------------
// testonly/vectors_test.go (main fbbcd741c3d1)
//
// Lines 26-30: these tests reproduce the accumulated test vectors of the
// "Subtree Test Vectors" appendix of draft-ietf-plants-merkle-tree-certs:
// for trees of sizes up to 130 they fold the output of each subtree
// algorithm over every valid input into one rolling SHA-256 and compare it
// with the value published in the draft.
//
// The implementation pinned here (v0.0.2) predates the subtree API
// (testonly.Tree.SubtreeHashAt, SubtreeInclusionProof, proof.SubtreeInclusion),
// so the loops below take the two tree methods as parameters. check.go passes
// the RFC 9162 section 2.1 reading of a subtree [start, end): MTH(D[start:end])
// and PATH(index - start, D[start:end]), computed once with the
// implementation (testonly.Tree over the leaf range) and once with the
// verbatim reference functions on crypto/sha256, and requires both published
// digests from both. Only the start = 0 rows are ordinary RFC 9162 tree
// hashes and inclusion proofs; the start > 0 rows are the draft's subtree
// semantics and are used here only inside the digests.
// ---------------------------------------------------------------------------

// subtreeVectorMax is testonly/vectors_test.go:32.
const subtreeVectorMax = uint64(130)

// subtreeVectorEntries is the leaf data of subtreeVectorTree,
// testonly/vectors_test.go:34-42 ("leaf values d[0] = 0x00, d[1] = 0x01, and
// so on"); upstream appends these entries to a testonly.Tree over
// rfc6962.DefaultHasher (newTree, testonly/tree_test.go:262-266).
func subtreeVectorEntries() [][]byte {
	entries := make([][]byte, subtreeVectorMax)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	return entries
}

// writeProofLine is testonly/vectors_test.go:44-60, with t.Fatalf replaced by
// a returned error.
func writeProofLine(w io.Writer, prefix string, proof [][]byte) error {
	if _, err := io.WriteString(w, prefix); err != nil {
		return fmt.Errorf("io.WriteString: %v", err)
	}
	for _, h := range proof {
		if _, err := fmt.Fprintf(w, " %x", h); err != nil {
			return fmt.Errorf("fmt.Fprintf: %v", err)
		}
	}
	if _, err := io.WriteString(w, "\n"); err != nil {
		return fmt.Errorf("io.WriteString: %v", err)
	}
	return nil
}

// subtreeHashVectorsWant is the literal of TestSubtreeHashVectors,
// testonly/vectors_test.go:77.
const subtreeHashVectorsWant = "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"

// subtreeInclusionProofVectorsWant is the literal of
// TestSubtreeInclusionProofVectors, testonly/vectors_test.go:100.
const subtreeInclusionProofVectorsWant = "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"

// subtreeHashVectorsDigest is the body of TestSubtreeHashVectors,
// testonly/vectors_test.go:62-81, with two substitutions: the method
// tree.SubtreeHashAt(start, end) is the parameter subtreeHashAt, and
// t.Fatalf becomes a returned error. It returns the rolling digest, and the
// number of rows folded into it.
func subtreeHashVectorsDigest(subtreeHashAt func(start, end uint64) []byte) (string, int, error) {
	rows := 0
	h := sha256.New()
	for end := range subtreeVectorMax + 1 {
		for start := range end + 1 {
			if err := isSubtreeValid(start, end); err != nil {
				continue
			}
			subtreeHash := subtreeHashAt(start, end)
			if _, err := fmt.Fprintf(h, "[%d, %d) %x\n", start, end, subtreeHash); err != nil {
				return "", rows, fmt.Errorf("fmt.Fprintf: %v", err)
			}
			rows++
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), rows, nil
}

// subtreeInclusionProofVectorsDigest is the body of
// TestSubtreeInclusionProofVectors, testonly/vectors_test.go:83-104, with the
// same two substitutions (tree.SubtreeInclusionProof is the parameter
// subtreeInclusionProof). It returns the rolling digest and the number of
// rows folded into it.
func subtreeInclusionProofVectorsDigest(subtreeInclusionProof func(index, start, end uint64) ([][]byte, error)) (string, int, error) {
	rows := 0
	h := sha256.New()
	for end := range subtreeVectorMax + 1 {
		for start := range end + 1 {
			if err := isSubtreeValid(start, end); err != nil {
				continue
			}
			for index := start; index < end; index++ {
				proof, err := subtreeInclusionProof(index, start, end)
				if err != nil {
					return "", rows, fmt.Errorf("SubtreeInclusionProof(%d, %d, %d): %v", index, start, end, err)
				}
				if err := writeProofLine(h, fmt.Sprintf("%d [%d, %d)", index, start, end), proof); err != nil {
					return "", rows, err
				}
				rows++
			}
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), rows, nil
}

// ---------------------------------------------------------------------------
// testonly/tree.go (main fbbcd741c3d1), lines 162-198, verbatim.
// ---------------------------------------------------------------------------

// isSubtreeValid returns whether a subtree covers a valid range.
// A subtree is valid if there exist a parent tree node to:
// - all the subtree nodes
// - no extra node to the left of the subtree
// - potentially extra nodes to the right of the subtree
func isSubtreeValid(start, end uint64) error {
	if start > end {
		return fmt.Errorf("start %d must be less than or equal to end %d", start, end)
	}
	if start == 0 {
		return nil
	}
	if start == end {
		return nil
	}

	l := end - start

	// special-case large subtree to avoid panic
	if l > uint64(1)<<63 {
		return fmt.Errorf("start %d must be 0 when subtree length %d > 1<<63", start, l)
	}
	if bc := bitCeil(l); start&(bc-1) != 0 {
		return fmt.Errorf("start %d not a multiple of bit_ceil(end - start) = %d", start, bc)
	}

	return nil
}

// bitCeil returns the smallest power of 2 larger than or equal to n.
// MUST NOT be used with n larger than uint64(1)<<63.
func bitCeil(n uint64) uint64 {
	if n <= 1 {
		return 1
	}
	return uint64(1) << bits.Len64(n-1)
}
