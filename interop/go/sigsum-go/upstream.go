// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0 AND BSD-2-Clause
//
// This file contains material copied from sigsum.org/sigsum-go@v0.14.1 (git
// tag v0.14.1, commit ea106fe53c454bc5b8ece2ba56afc43d0f1f09dc): lines of
// pkg/proof/proof_test.go, pkg/merkle/tree_test.go,
// pkg/types/tree_head_test.go, tests/sigsum-submit-test and doc/tools.md,
// and two error message fragments of pkg/merkle/verify.go. That material is
// BSD-2-Clause, Copyright (c) 2021, The Sigsum Project Authors. Its license
// text is LICENSE-sigsum-go in this directory; NOTICE lists it.

package main

// Every block names its upstream file and line range. The lines between a
// "// verbatim <file>:<a>-<b>" comment and the next "// end verbatim" comment
// are byte-identical to those upstream lines (tabs included). The lines
// around them (declarations, returns, shims) are ours, and so is any line
// that ends in "// added". A "// verbatim text <file>:<a>-<b>" comment
// marks the raw string declared on the next line: the lines between the
// line that opens it and the line that closes it are those upstream lines,
// byte for byte.

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"slices"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/key"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/types"
)

// Package-level names so that verbatim lines from package merkle's tests
// compile unchanged in package main. Each is the implementation's own function.
var (
	HashLeafNode     = merkle.HashLeafNode
	HashInteriorNode = merkle.HashInteriorNode
	NewTree          = merkle.NewTree
	VerifyInclusion  = merkle.VerifyInclusion
)

// Type names so that verbatim lines from package types' tests compile unchanged.
type (
	SignedTreeHead = types.SignedTreeHead
	TreeHead       = types.TreeHead
)

// fatalT stands in for *testing.T in the copied helpers: Fatal and Fatalf panic,
// Errorf records the failure so the caller can report it.
type fatalT struct{ errs *[]string }

func (t fatalT) Fatal(args ...any)                 { panic(fmt.Sprint(args...)) }
func (t fatalT) Fatalf(format string, args ...any) { panic(fmt.Sprintf(format, args...)) }
func (t fatalT) Errorf(format string, args ...any) {
	if t.errs != nil {
		*t.errs = append(*t.errs, fmt.Sprintf(format, args...))
	}
}

// ---------------------------------------------------------------------------
// pkg/proof/proof_test.go

// TestASCII table. Struct shape from pkg/proof/proof_test.go:14-17; the
// entries sit at upstream's nesting depth so gofmt leaves them unchanged.
var testASCIITable = func() []struct {
	desc  string
	ascii string
} {
	return []struct {
		desc  string
		ascii string
	}{
		// verbatim pkg/proof/proof_test.go:18-38
		// Examples from running sigsum-submit-test.
		{"size 1", `version=2
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 90c47772e2758fac56740ad52913af66874dc49b31ef21e4fab544a2836b7d9991f07559792f22c617c172e10391317b4a0a4396c4eb9cfc1871ed07a360240f

size=1
root_hash=b02bd71073448d7a3ee402892f96c9d78b712242deed7e6fd8a98abcde33f46d
signature=2eb4bfb59aa08531f325b8b233859d5c62187a311c7bb32e4cbd61e3a2b458d4e4451cfeb8a920d3cb4f755ed2f5f895628c0d92463f6f2d7d12fdf56f070d04
`},
		{"size 4", `version=2
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 5c46852140e41b49925f8c93dee5c3e776ababdd230425d17f44b519f5565e0026f86aea998ccb7685fbc672c7d016a3940db5d684279a39c870318c840bf002

size=4
root_hash=ca5e9898dd77d24019bee526e3cafa2c0c2c47e82897f5d237fdfa6f132ec0a8
signature=207347dc94e5ca8525a2d03901223064c96fa7a245f502c64b6dff2d50d6dd3bc9e809f81e0867b839e41e73296876dcef514ec5f323ccadd3cc5b0b0049730f

leaf_index=3
node_hash=8a419a476109a749732ee0d9845470c995ae6502225647f4b3bbb1dff61a5b4f
node_hash=eb94766b094058835d61c551a8ef581e8242ea419b665a2d2043291b98524e14
`},
		// end verbatim
	}
}()

// TestASCIIV1 table. Struct shape from pkg/proof/proof_test.go:61-65.
var testASCIIV1Table = func() []struct {
	desc    string
	asciiV2 string
	asciiV1 string
} {
	return []struct {
		desc    string
		asciiV2 string
		asciiV1 string
	}{
		// verbatim pkg/proof/proof_test.go:66-111
		// Examples from running sigsum-submit-test.
		{
			"size 1",
			`version=2
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 90c47772e2758fac56740ad52913af66874dc49b31ef21e4fab544a2836b7d9991f07559792f22c617c172e10391317b4a0a4396c4eb9cfc1871ed07a360240f

size=1
root_hash=b02bd71073448d7a3ee402892f96c9d78b712242deed7e6fd8a98abcde33f46d
signature=2eb4bfb59aa08531f325b8b233859d5c62187a311c7bb32e4cbd61e3a2b458d4e4451cfeb8a920d3cb4f755ed2f5f895628c0d92463f6f2d7d12fdf56f070d04
`,
			`version=1
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=5cc0 518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 90c47772e2758fac56740ad52913af66874dc49b31ef21e4fab544a2836b7d9991f07559792f22c617c172e10391317b4a0a4396c4eb9cfc1871ed07a360240f

size=1
root_hash=b02bd71073448d7a3ee402892f96c9d78b712242deed7e6fd8a98abcde33f46d
signature=2eb4bfb59aa08531f325b8b233859d5c62187a311c7bb32e4cbd61e3a2b458d4e4451cfeb8a920d3cb4f755ed2f5f895628c0d92463f6f2d7d12fdf56f070d04
`},
		{
			"size 4",
			`version=2
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 5c46852140e41b49925f8c93dee5c3e776ababdd230425d17f44b519f5565e0026f86aea998ccb7685fbc672c7d016a3940db5d684279a39c870318c840bf002

size=4
root_hash=ca5e9898dd77d24019bee526e3cafa2c0c2c47e82897f5d237fdfa6f132ec0a8
signature=207347dc94e5ca8525a2d03901223064c96fa7a245f502c64b6dff2d50d6dd3bc9e809f81e0867b839e41e73296876dcef514ec5f323ccadd3cc5b0b0049730f

leaf_index=3
node_hash=8a419a476109a749732ee0d9845470c995ae6502225647f4b3bbb1dff61a5b4f
node_hash=eb94766b094058835d61c551a8ef581e8242ea419b665a2d2043291b98524e14
`,
			`version=1
log=24a68b92fe18d8fb6dce4b3a3c8ac25453eb4ee6c3bb575651bdfbda95e2e952
leaf=7e28 518ac523804cb74e2cb41f219aed1bfccc76a1202d8b891eed1a7cf3791eab9c 5c46852140e41b49925f8c93dee5c3e776ababdd230425d17f44b519f5565e0026f86aea998ccb7685fbc672c7d016a3940db5d684279a39c870318c840bf002

size=4
root_hash=ca5e9898dd77d24019bee526e3cafa2c0c2c47e82897f5d237fdfa6f132ec0a8
signature=207347dc94e5ca8525a2d03901223064c96fa7a245f502c64b6dff2d50d6dd3bc9e809f81e0867b839e41e73296876dcef514ec5f323ccadd3cc5b0b0049730f

leaf_index=3
node_hash=8a419a476109a749732ee0d9845470c995ae6502225647f4b3bbb1dff61a5b4f
node_hash=eb94766b094058835d61c551a8ef581e8242ea419b665a2d2043291b98524e14
`,
		},
		// end verbatim
	}
}()

// TestVerifyNoCosignatures inputs, pkg/proof/proof_test.go:132-161.
func testVerifyNoCosignaturesInputs() (string, crypto.Hash, crypto.PublicKey, crypto.PublicKey) {
	t := fatalT{}
	// verbatim pkg/proof/proof_test.go:133-151
	// Example from running sigsum-submit-test.
	proofASCII := `version=2
log=1f8d4547082a5985ad0e59ffe219f7a065e09c6b77a0012daf276e5dd1805b4b
leaf=69512577a0f3c2695011ddc549756099017b7e2c8390341cbb24c57e886775f1 262737d935123272b9e3265fe2e38a014a9c1b13951e864737666251ada26dabbc6e699a4e527ec52a0be970e158abef35f087766d18d560853a44855119cf01

size=4
root_hash=7bca01e88737999fde5c1d6ecac27ae3cb49e14f21bcd3e7245c276877b899c9
signature=c60e5151b9d0f0efaf57022c0ec306c0f0275afef69333cc89df4fda328c87949fcfa44564f35020938a4cd6c1c50bc0349b2f54b82f5f6104b9cd52be2cd90e

leaf_index=3
node_hash=e7d222a285ca81fdc76bfcd5513408c87dd42a18e03d6c3b672a05982163c01b
node_hash=15cdc42440689a6f7599e09f61a4d638420cb58662f5994def1624ea4d923879
`
	msg := crypto.Hash{
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'f', 'o', 'o', '-', '4', '\n',
	}
	logKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6kw3w2BWjlKLdrtnv4IaN+zg8/RpKGA98AbbTwjpdQ")
	submitKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMCMTGNMNe1HP2us/dR5dBpyrSPDgPQ9mX5j9iqbLIS+")
	// end verbatim
	return proofASCII, msg, logKey, submitKey
}

// TestVerify inputs, pkg/proof/proof_test.go:163-200.
func testVerifyInputs() (string, crypto.Hash, crypto.PublicKey, crypto.PublicKey, crypto.PublicKey) {
	t := fatalT{}
	// verbatim pkg/proof/proof_test.go:164-184
	// Example from running sigsum-submit-witness-test.
	proofASCII := `version=2
log=7c5fafc796c201e0fcd7567c5033a2777ec28363f54ea0ba97b57bece0d96acd
leaf=8a578b9649ba01b7d29dd557906975d68a3aec50e3f9c08690420b8c6426856d 79b489a38548a67d78f06221b014d41be58b703237d17b4f203f0dd4ead9e2597149c2f118894581ce7473a61fa880716af6ff2138bade2cecc4b297099bf104

size=4
root_hash=3ddc56fd46e71e517b6936b977a457da7d398108141fcdf5c8386cdd724ab7a8
signature=ccbdd8c784726b732b8edd2039fbad5506e4acccd56e3e5d86c0ee109b3d2662e6881fe3d09fc48f9ddd31494463c5ec44926ff9158785ad1dd9b5d6434b0804
cosignature=bd8385aa82e07c3e1e297a1600c12bb25ce7a9490b5c1287ec30e09ac4c8b884 1683202758 e8d6c447d7847d5c1431ef86f8c60fa0cbacd975388b2a8f202fe4b0f9d0d544989c9d9351752d86aae2df72b9d7135b6b09de2ccaa6d68edf638105d69be609

leaf_index=3
node_hash=61010ae798308f5b97237615ab8c1b14f2c782c37616e97d0a170b617bc7a4ce
node_hash=a5c3752be610d605ce5c64ee2e28ee5b94a1cc0a68742f18f24c9b5c82d07298
`
	msg := crypto.Hash{
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'f', 'o', 'o', '-', '4', '\n',
	}
	logKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKwmwKhVrEUaZTlHjhoWA4jwJLOF8TY+/NpHAXAHbAHl")
	submitKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMdLcxVjCAQUHbD4jCfFP+f8v1nmyjWkq6rXiexrK8II")
	witnessKey := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMvjV+a0ZASecDt75siSARk6zCoYwJWwaRqvULmx4VeK")
	// end verbatim
	return proofASCII, msg, logKey, submitKey, witnessKey
}

// mustParsePublicKey, pkg/proof/proof_test.go:201-207 (signature line ours:
// upstream takes *testing.T).
func mustParsePublicKey(t fatalT, ascii string) crypto.PublicKey {
	// verbatim pkg/proof/proof_test.go:202-207
	key, err := key.ParsePublicKey(ascii)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// end verbatim

// ---------------------------------------------------------------------------
// pkg/merkle/tree_test.go

// mustHashFromHex, pkg/merkle/tree_test.go:354-360 (signature line ours:
// upstream takes *testing.T).
func mustHashFromHex(t fatalT, hex string) crypto.Hash {
	// verbatim pkg/merkle/tree_test.go:355-360
	h, err := crypto.HashFromHex(hex)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// end verbatim

// verbatim pkg/merkle/tree_test.go:362-370
func newLeaves(n int) []crypto.Hash {
	hashes := make([]crypto.Hash, n)
	for i := 0; i < n; i++ {
		var blob [8]byte
		binary.BigEndian.PutUint64(blob[:], uint64(i))
		hashes[i] = HashLeafNode(blob[:])
	}
	return hashes
}

// end verbatim

// TestGetRootHash expectations for sizes 0..5, pkg/merkle/tree_test.go:62-87.
// Element i of the result is the root upstream asserts for tree size i.
func testGetRootHashWants() []crypto.Hash {
	t := fatalT{}
	// verbatim pkg/merkle/tree_test.go:63-66
	hashes := newLeaves(5)
	h01 := HashInteriorNode(&hashes[0], &hashes[1])
	h23 := HashInteriorNode(&hashes[2], &hashes[3])
	h0123 := HashInteriorNode(&h01, &h23)
	// end verbatim
	return []crypto.Hash{
		// verbatim pkg/merkle/tree_test.go:70-75
		mustHashFromHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		hashes[0],
		h01,
		HashInteriorNode(&h01, &hashes[2]),
		h0123,
		HashInteriorNode(&h0123, &hashes[4]),
		// end verbatim
	}
}

// TestInclusion expected paths at size 5, pkg/merkle/tree_test.go:89-118.
// Element i of the result is the path upstream asserts ProveInclusion(i, 5) returns.
func testInclusionPaths() [][]crypto.Hash {
	// verbatim pkg/merkle/tree_test.go:90-93
	hashes := newLeaves(5)
	h01 := HashInteriorNode(&hashes[0], &hashes[1])
	h23 := HashInteriorNode(&hashes[2], &hashes[3])
	h0123 := HashInteriorNode(&h01, &h23)
	// end verbatim
	return [][]crypto.Hash{
		// verbatim pkg/merkle/tree_test.go:104-108
		[]crypto.Hash{hashes[1], h23, hashes[4]},
		[]crypto.Hash{hashes[0], h23, hashes[4]},
		[]crypto.Hash{hashes[3], h01, hashes[4]},
		[]crypto.Hash{hashes[2], h01, hashes[4]},
		[]crypto.Hash{h0123},
		// end verbatim
	}
}

// TestGetRootHash, pkg/merkle/tree_test.go:62-87, run as upstream wrote it.
// The body is upstream lines 63-86, unchanged; the signature line is ours
// (upstream takes *testing.T). t.Fatalf panics and t.Errorf records a failure.
func testGetRootHash(t fatalT) {
	// verbatim pkg/merkle/tree_test.go:63-86
	hashes := newLeaves(5)
	h01 := HashInteriorNode(&hashes[0], &hashes[1])
	h23 := HashInteriorNode(&hashes[2], &hashes[3])
	h0123 := HashInteriorNode(&h01, &h23)

	tree := NewTree()
	for i, want := range []crypto.Hash{
		mustHashFromHex(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		hashes[0],
		h01,
		HashInteriorNode(&h01, &hashes[2]),
		h0123,
		HashInteriorNode(&h0123, &hashes[4]),
	} {
		if tree.Size() < uint64(i) {
			if !tree.AddLeafHash(&hashes[tree.Size()]) {
				t.Fatalf("AddLeafHash failed at size %d", tree.Size())
			}
		}
		if got := tree.GetRootHash(); got != want {
			t.Errorf("bad root hash for size %d\n  got: %x\n want: %x",
				i, got, want)
		}
	}
	// end verbatim
}

// TestInclusion, pkg/merkle/tree_test.go:89-118, run as upstream wrote it.
// The body is upstream lines 90-117, unchanged; the signature line is ours.
func testInclusion(t fatalT) {
	// verbatim pkg/merkle/tree_test.go:90-117
	hashes := newLeaves(5)
	h01 := HashInteriorNode(&hashes[0], &hashes[1])
	h23 := HashInteriorNode(&hashes[2], &hashes[3])
	h0123 := HashInteriorNode(&h01, &h23)

	tree := NewTree()
	for _, h := range hashes {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
	}

	// Inclusion path for index i and size 5.
	for i, p := range [][]crypto.Hash{
		[]crypto.Hash{hashes[1], h23, hashes[4]},
		[]crypto.Hash{hashes[0], h23, hashes[4]},
		[]crypto.Hash{hashes[3], h01, hashes[4]},
		[]crypto.Hash{hashes[2], h01, hashes[4]},
		[]crypto.Hash{h0123},
	} {
		if proof, err := tree.ProveInclusion(uint64(i), 5); err != nil || !slices.Equal(proof, p) {
			if err != nil {
				t.Fatalf("ProveInclusion %d, 5 failed: %v", i, err)
			}
			t.Errorf("unexpected inclusion path\n  got: %x\n want: %x\n",
				proof, p)
		}
	}
	// end verbatim
}

// TestConsistency formula node hashes over newLeaves(7),
// pkg/merkle/tree_test.go:256-262 (the consistency paths themselves are out
// of the fixture schema).
// It returns hashes, h01, h23, h0123, h45, h456.
func testConsistencyNodes() ([]crypto.Hash, crypto.Hash, crypto.Hash, crypto.Hash, crypto.Hash, crypto.Hash) {
	// verbatim pkg/merkle/tree_test.go:257-262
	hashes := newLeaves(7)
	h01 := HashInteriorNode(&hashes[0], &hashes[1])
	h23 := HashInteriorNode(&hashes[2], &hashes[3])
	h0123 := HashInteriorNode(&h01, &h23)
	h45 := HashInteriorNode(&hashes[4], &hashes[5])
	h456 := HashInteriorNode(&h45, &hashes[6])
	// end verbatim
	return hashes, h01, h23, h0123, h45, h456
}

// TestInclusionValid, pkg/merkle/tree_test.go:120-159, adapted: the body is
// upstream lines 121-158 in order and unchanged; the two lines ending in
// "// added" only record the proof that was just checked (they make no rand
// calls). record gets bitToFlip = hashToFlip = -1 for the unmodified proof,
// which upstream asserts VerifyInclusion accepts, and the flip indexes for
// the corrupted copy, which upstream asserts VerifyInclusion rejects.
func testInclusionValid(t fatalT, record func(i, n int, leaf crypto.Hash, proof []crypto.Hash, root crypto.Hash, bitToFlip, hashToFlip int)) {
	// verbatim pkg/merkle/tree_test.go:121-158 (plus the two "// added" lines)
	hashes := newLeaves(100)

	rootHashes := []crypto.Hash{}
	tree := NewTree()
	for _, h := range hashes {
		if !tree.AddLeafHash(&h) {
			t.Fatalf("AddLeafHash failed at size %d", tree.Size())
		}
		rootHashes = append(rootHashes, tree.GetRootHash())
	}

	r := rand.New(rand.NewSource(17))

	for i := 0; i < len(hashes); i++ {
		for n := i + 1; n <= len(hashes); n++ {
			proof, err := tree.ProveInclusion(uint64(i), uint64(n))
			if err != nil {
				t.Fatalf("ProveInclusion %d, %d failed: %v", i, n, err)
			}
			leaf := hashes[i]
			if err := VerifyInclusion(&leaf, uint64(i), uint64(n), &rootHashes[n-1], proof); err != nil {
				t.Errorf("inclusion proof not valid, i %d, n %d: %v\n  proof: %x\n",
					i, n, err, proof)
			}
			record(i, n, leaf, slices.Clone(proof), rootHashes[n-1], -1, -1) // added
			bitToFlip := r.Intn(crypto.HashSize * 8)
			hashToFlip := r.Intn(len(proof) + 1)
			if hashToFlip > 0 {
				proof[hashToFlip-1][bitToFlip/8] ^= 1 << (bitToFlip % 8)
			} else {
				leaf[bitToFlip/8] ^= 1 << (bitToFlip % 8)
			}
			if err := VerifyInclusion(&leaf, uint64(i), uint64(n), &rootHashes[n-1], proof); err == nil {
				t.Errorf("inclusion proof should have failed, i %d, n %d: flipped bit %d of hash %d\n",
					i, n, bitToFlip, hashToFlip)
			}
			record(i, n, leaf, slices.Clone(proof), rootHashes[n-1], bitToFlip, hashToFlip) // added
		}

	}
	// end verbatim
}

// ---------------------------------------------------------------------------
// pkg/types/tree_head_test.go

// TestSignedTreeHeadVerify inputs, pkg/types/tree_head_test.go:151-167: the
// signed tree head of the TestVerifyNoCosignatures proof and its log key.
func testSignedTreeHeadVerifyInputs() (crypto.PublicKey, SignedTreeHead) {
	t := fatalT{}
	// verbatim pkg/types/tree_head_test.go:152-159
	pub := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN6kw3w2BWjlKLdrtnv4IaN+zg8/RpKGA98AbbTwjpdQ")
	sth := SignedTreeHead{
		TreeHead: TreeHead{
			Size:     4,
			RootHash: mustHashFromHex(t, "7bca01e88737999fde5c1d6ecac27ae3cb49e14f21bcd3e7245c276877b899c9"),
		},
		Signature: mustSignatureFromHex(t, "c60e5151b9d0f0efaf57022c0ec306c0f0275afef69333cc89df4fda328c87949fcfa44564f35020938a4cd6c1c50bc0349b2f54b82f5f6104b9cd52be2cd90e"),
	}
	// end verbatim
	return pub, sth
}

// mustSignatureFromHex, pkg/types/tree_head_test.go:449-455 (signature line
// ours: upstream takes *testing.T).
func mustSignatureFromHex(t fatalT, hex string) crypto.Signature {
	// verbatim pkg/types/tree_head_test.go:450-455
	s, err := crypto.SignatureFromHex(hex)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// end verbatim

// ---------------------------------------------------------------------------
// tests/sigsum-submit-test

// submitTestMessage returns the message that tests/sigsum-submit-test submits
// as proof number x. Lines 31-38 of that script follow, each prefixed with
// "//" and a tab and otherwise verbatim:
//
//	for x in $(seq 5); do
//	    echo >&2 "submit $x"
//	    # Must be exactly 32 bytes
//	    printf "%31s\n" "foo-$x" \
//		| ./bin/sigsum-submit --diagnostics=warning --timeout=5s \
//		     --token-domain test.sigsum.org --token-signing-key test.token.key \
//		     --raw-hash -o "test.$x.proof" --signing-key test.submit.key --policy test.policy
//	done
//
// The message is printf "%31s\n" "foo-$x": 31 characters right-justified
// with spaces, then a newline, 32 bytes in all. With --raw-hash these 32
// bytes are the message itself, and the leaf checksum is SHA-256(message)
// (pkg/proof/proof.go:169, pkg/types/leaf.go:34-37).
func submitTestMessage(x int) crypto.Hash {
	s := fmt.Sprintf("%31s\n", fmt.Sprintf("foo-%d", x)) // Go's %31s pads like printf(1)
	if len(s) != crypto.HashSize {
		panic(fmt.Sprintf("message for x=%d is %d bytes, want 32", x, len(s)))
	}
	var m crypto.Hash
	copy(m[:], s)
	return m
}

// ---------------------------------------------------------------------------
// pkg/merkle/verify.go

// Fragments of merkle.VerifyInclusion's two refusal messages, "proof input is
// malformed: index out of range" (pkg/merkle/verify.go:104) and "proof input
// is malformed: path length %d, should be %d" (line 108). -ours uses them to
// tell which check refused a proof.
const (
	errIndexOutOfRange = "index out of range"
	errPathLength      = "path length"
)

// ---------------------------------------------------------------------------
// doc/tools.md
//
// The sigsum-submit examples (doc/tools.md:419-471) submit two messages to
// the poc.sigsum.org log and print the Sigsum proofs the log returned. By
// default the message submitted is the SHA256 hash of the input (lines
// 343-344), so the input is the echo output: the quoted text plus a newline.

// The example submitter public key in raw hex (the output of sigsum-key to-hex).
// verbatim text doc/tools.md:268-269
const docToolsSubmitKey = `
$ sigsum-key to-hex -k example.key.pub
e0863b18794d2150f3999590e0e508c09068b9883f05ea65f58cfc0827130e92
`

// The policy file for the poc.sigsum.org log (lines 423-426), without the code fence.
// verbatim text doc/tools.md:424-425
const docToolsPolicy = `
log 154f49976b59ff09a123675f58cb3e346e0455753c3c3b15d465dcb4f6512b0b https://poc.sigsum.org/jellyfish
quorum none
`

// Submitting "Hello old friend" to that log, and the size 3 proof it returned.
// verbatim text doc/tools.md:430-440
const docToolsSize3 = `
$ echo "Hello old friend" | sigsum-submit -k example.key -p example.policy
version=2
log=c9e525b98f412ede185ff2ac5abf70920a2e63a6ae31c88b1138b85de328706b
leaf=5aa7e6233f9f4d2efbeb9eeef766dce8ba2aa5e8cdd3f53da94b5d59e67d92fc 40160c833571c121bfdc6a02006053a80d3e91a8b73abb4dd0e07cc3098d8e58a41921d8f5649e9fb81c9b7c6b458747c4c3b49cc08c869867100a7f7be78902

size=3
root_hash=5b0cc467f86fdd57b371e434843b571a4cb47c6a64dad4bc80d96dd7d15c63a9
signature=f6a87ce27a6df207eaaee6589ab73ac8cb5bead7bd0c0fea65556d847d11f3baea8ebdc686730f64e38000c77f5327048e73e08b7dc4de04b91f65930bedc100

leaf_index=2
node_hash=ede77b77a3bba27ea0af640d37e58281aef4459d71afdf5cf442cee8f9bebf5d
`

// Creating the add-leaf request for "Hello again" (the first of two steps).
// verbatim text doc/tools.md:446-449
const docToolsRequest = `
$ echo "Hello again" | sigsum-submit -k example.key | tee example.req
message=07305a3200629a7b8a04f77008fa1b1f719fec3b60d4fdf2683ba60cf2956381
signature=aa5bd628d88be12d4f09feefe4bf65290b03bdeba8523fa38e396218140d79e0850132082914b08876cdc4a6041be8217402a57bfb8328310ad5407bc440060e
public_key=e0863b18794d2150f3999590e0e508c09068b9883f05ea65f58cfc0827130e92
`

// Submitting that request, and the size 4 proof it returned.
// verbatim text doc/tools.md:454-465
const docToolsSize4 = `
$ sigsum-submit -p example.policy < example.req
version=2
log=c9e525b98f412ede185ff2ac5abf70920a2e63a6ae31c88b1138b85de328706b
leaf=5aa7e6233f9f4d2efbeb9eeef766dce8ba2aa5e8cdd3f53da94b5d59e67d92fc aa5bd628d88be12d4f09feefe4bf65290b03bdeba8523fa38e396218140d79e0850132082914b08876cdc4a6041be8217402a57bfb8328310ad5407bc440060e

size=4
root_hash=fd23842c67ba396cbabaa22226f3cd7737a4cc9f36c897f4fce2cc5070925dc2
signature=fb573c4365ddc71110724f40dcbda62324d5c9b8e92d9e7cbda056f4c8e45e17018e72484c9d5af6e7c38b9705ed504375c3a03c7acc5abc3827dd042d1fe100

leaf_index=3
node_hash=4b3f8b78ae7fb7e6f6925d8a6f66af4d30de9b3e3a3f66cd4b0dba2c6b5b8725
node_hash=ede77b77a3bba27ea0af640d37e58281aef4459d71afdf5cf442cee8f9bebf5d
`
