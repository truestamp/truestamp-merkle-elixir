// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains material copied from github.com/codenotary/merkletree@v0.1.2:
// mth_test.go, tree_test.go and example_test.go (the line ranges are listed
// below), Copyright 2019-2020 vChain, Inc., licensed under the Apache License,
// Version 2.0 (LICENSE-codenotary-merkletree; see NOTICE).

package main

// Verbatim copies of test functions from github.com/codenotary/merkletree
// v0.1.2, Copyright 2019-2020 vChain, Inc., Apache-2.0
// (LICENSE-codenotary-merkletree):
//
//   mth_test.go:28-38      TestMTH             (roots of sizes 0..65 vs testRoots)
//   mth_test.go:39-62      TestMPath           (MPath vs testPaths, sizes 1..9)
//   tree_test.go:46-61     TestAppend          (incremental store roots vs testRoots)
//   tree_test.go:62-70     TestRoot            (empty store root, 1-leaf root)
//   tree_test.go:87-119    TestInclusionProof  (store proofs vs MPath, every at <= 64)
//   tree_test.go:120-147   TestVerifyInclusion (4 edge verdicts, then every leaf of sizes 1..65)
//   example_test.go:43-71  make7leaves         (the 7-leaf "d0".."d6" tree)
//   example_test.go:72-109 TestInclusionPath   (audit paths and verdicts in that tree)
//
// Each block between BEGIN and END is checked byte for byte against the
// vendored file in testdata/ on every run. The imports below are file scoped:
// "testing", "assert" and "fmt" resolve to the stand-ins under internal/, and
// the package-level names the copied code uses (MTH, MPath, Path,
// InclusionProof, NewMemStore, Append, Root, Depth, LeafHash, Storer) are
// thin wrappers over the real module in shims.go. Path.VerifyInclusion
// records each call, and the assert stand-in attaches upstream's asserted
// verdict to it.

import (
	"crypto/sha256"
	"math"
	"strconv"

	"github.com/truestamp/truestamp-merkle-elixir/interop/go/codenotary-merkletree/internal/assert"
	fmt "github.com/truestamp/truestamp-merkle-elixir/interop/go/codenotary-merkletree/internal/quietfmt"
	"github.com/truestamp/truestamp-merkle-elixir/interop/go/codenotary-merkletree/internal/testing"
)

// BEGIN mth_test.go:28-38
func TestMTH(t *testing.T) {

	D := [][]byte{}
	assert.Equal(t, sha256.Sum256(nil), MTH(D))
	for index := uint64(0); index <= 64; index++ {
		b := []byte(strconv.FormatUint(index, 10))
		D = append(D, b)
		assert.Equal(t, testRoots[index], MTH(D))
	}
}

// END

// BEGIN mth_test.go:39-62
func TestMPath(t *testing.T) {

	D := [][]byte{}

	assert.Nil(t, MPath(0, D)) // undefined path

	for index := uint64(0); index <= 8; index++ {
		b := []byte(strconv.FormatUint(index, 10))
		D = append(D, b)

		assert.Nil(t, MPath(index+1, D)) // undefined path

		for i := uint64(0); i <= index; i++ {
			fmt.Println("\n\n-------- TEST", index+1, "--------")
			path := MPath(i, D)
			fmt.Printf(" len(path)=%d\n", len(path))
			for d, h := range path {
				fmt.Printf("%d) %.2x\n", d, h[0])
			}
			assert.Equal(t, testPaths[index][i], path)
		}
	}
}

// END

// BEGIN tree_test.go:46-61
func TestAppend(t *testing.T) {
	s := NewMemStore()
	assert.Equal(t, -1, Depth(s))

	for index := uint64(0); index <= 64; index++ {
		b := []byte(strconv.FormatUint(index, 10))
		Append(s, b)

		assert.Equal(t, index, uint64(s.Width()-1))
		d := int(math.Ceil(math.Log2(float64(index + 1))))
		assert.Equal(t, d, Depth(s))

		assert.Equal(t, testRoots[index], Root(s))
	}
}

// END

// BEGIN tree_test.go:62-70
func TestRoot(t *testing.T) {
	s := NewMemStore()
	assert.Equal(t, sha256.Sum256(nil), Root(s))

	value := []byte("some value")
	Append(s, value)
	assert.Equal(t, LeafHash(value), Root(s))
}

// END

// BEGIN tree_test.go:87-119
func TestInclusionProof(t *testing.T) {

	s := NewMemStore()
	D := [][]byte{}
	for index := uint64(0); index <= 64; index++ {
		v := []byte(strconv.FormatUint(index, 10))
		D = append(D, v)
		Append(s, v)

		// test out of range
		assert.Nil(t, InclusionProof(s, index+1, index))
		assert.Nil(t, InclusionProof(s, index, index+1))

		for at := uint64(0); at <= index; at++ {
			for i := uint64(0); i <= at; i++ {
				fmt.Printf("\n\n-----------------\nn=%d at=%d i=%d\n", index+1, at, i)
				path := InclusionProof(s, at, i)

				expected := MPath(i, D[0:at+1])

				if !assert.Len(t, path, len(expected)) {
					return
				}
				for k, v := range path {
					if !assert.Equal(t, expected[k], v) {
						return
					}
				}
			}
		}
	}
}

// END

// BEGIN tree_test.go:120-147
func TestVerifyInclusion(t *testing.T) {

	path := Path{}
	assert.True(t, path.VerifyInclusion(0, 0, [sha256.Size]byte{}, [sha256.Size]byte{}))

	assert.False(t, path.VerifyInclusion(0, 1, [sha256.Size]byte{}, [sha256.Size]byte{}))
	assert.False(t, path.VerifyInclusion(1, 0, [sha256.Size]byte{}, [sha256.Size]byte{}))
	assert.False(t, path.VerifyInclusion(1, 1, [sha256.Size]byte{}, [sha256.Size]byte{}))

	s := NewMemStore()
	D := [][]byte{}
	for index := uint64(0); index <= 64; index++ {
		v := []byte(strconv.FormatUint(index, 10))
		D = append(D, v)
		Append(s, v)
		for at := uint64(0); at <= index; at++ {
			for i := uint64(0); i <= at; i++ {
				path := MPath(i, D[0:at+1])
				isV := Path(path).VerifyInclusion(at, i, testRoots[at], *s.Get(0, i))
				assert.True(t, isV)
				if !isV {
					return
				}
			}
		}
	}
}

// END

// BEGIN example_test.go:43-71
func make7leaves() (m map[string][sha256.Size]byte, D [][]byte, s Storer) {
	m = make(map[string][sha256.Size]byte)
	s = NewMemStore()
	for i := 0; i < 7; i++ {
		v := "d" + strconv.FormatInt(int64(i), 10)
		D = append(D, []byte(v))
		Append(s, []byte(v))
	}

	m["a"] = *s.Get(0, 0)
	m["b"] = *s.Get(0, 1)
	m["c"] = *s.Get(0, 2)
	m["d"] = *s.Get(0, 3)
	m["e"] = *s.Get(0, 4)
	m["f"] = *s.Get(0, 5)

	m["g"] = *s.Get(1, 0)
	m["h"] = *s.Get(1, 1)
	m["i"] = *s.Get(1, 2)
	m["j"] = *s.Get(0, 6)

	m["k"] = *s.Get(2, 0)
	m["l"] = *s.Get(2, 1)

	m["hash"] = *s.Get(3, 0)

	return
}

// END

// BEGIN example_test.go:72-109
func TestInclusionPath(t *testing.T) {
	m, D, s := make7leaves()

	// The audit path for d0 is [b, h, l].
	path := InclusionProof(s, 6, 0)
	assert.Equal(t, Path(MPath(0, D)), path)
	assert.Len(t, path, 3)
	assert.Equal(t, m["b"], path[0])
	assert.Equal(t, m["h"], path[1])
	assert.Equal(t, m["l"], path[2])
	assert.True(t, path.VerifyInclusion(6, 0, m["hash"], m["a"]))

	// The audit path for d3 is [c, g, l].
	path = InclusionProof(s, 6, 3)
	assert.Equal(t, Path(MPath(3, D)), path)
	assert.Len(t, path, 3)
	assert.Equal(t, m["c"], path[0])
	assert.Equal(t, m["g"], path[1])
	assert.Equal(t, m["l"], path[2])
	assert.True(t, path.VerifyInclusion(6, 3, m["hash"], m["d"]))

	// The audit path for d4 is [f, j, k].
	path = InclusionProof(s, 6, 4)
	assert.Equal(t, Path(MPath(4, D)), path)
	assert.Len(t, path, 3)
	assert.Equal(t, m["f"], path[0])
	assert.Equal(t, m["j"], path[1])
	assert.Equal(t, m["k"], path[2])

	// The audit path for d6 is [i, k]
	path = InclusionProof(s, 6, 6)
	assert.Equal(t, Path(MPath(6, D)), path)
	assert.Len(t, path, 2)
	assert.Equal(t, m["i"], path[0])
	assert.Equal(t, m["k"], path[1])
	assert.True(t, path.VerifyInclusion(6, 6, m["hash"], m["j"]))
}

// END
