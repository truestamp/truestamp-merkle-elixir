// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains code and literals copied from github.com/transparency-dev/merkle@v0.0.2
// (Apache-2.0, Copyright Google LLC): testonly/constants.go,
// rfc6962/rfc6962_test.go, proof/verify_test.go, testonly/reference_test.go,
// compact/range_test.go, proof/proof_test.go and testonly/tree_test.go, at the
// line ranges named below. The upstream license is vendored as
// LICENSE-transparency-dev-merkle; see NOTICE.

package main

// Verbatim copies of the fixture literals and fixture-generating logic from
// github.com/transparency-dev/merkle@v0.0.2 (Apache-2.0). The exported
// testonly functions are also importable, but the _test.go literals are not,
// so every table below is copied character for character from the named file
// and line range, then checked against the implementation's exported
// functions by check.go.

import (
	"encoding/hex"
	"fmt"
	"math/bits"
	"strconv"

	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/compact"
)

// ---------------------------------------------------------------------------
// testonly/constants.go (v0.0.2)
// ---------------------------------------------------------------------------

// LeafInputs is testonly/constants.go:21-33.
func LeafInputs() [][]byte {
	return [][]byte{
		hd(""),
		hd("00"),
		hd("10"),
		hd("2021"),
		hd("3031"),
		hd("40414243"),
		hd("5051525354555657"),
		hd("606162636465666768696a6b6c6d6e6f"),
	}
}

// NodeHashes is testonly/constants.go:39-60.
func NodeHashes() [][][]byte {
	return [][][]byte{{
		hd("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
		hd("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
		hd("0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7"),
		hd("07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7"),
		hd("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
		hd("4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658"),
		hd("b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f"),
		hd("46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1"),
	}, {
		hd("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
		hd("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
		hd("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a"),
		hd("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
	}, {
		hd("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
		hd("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"),
	}, {
		hd("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"),
	}}
}

// RootHashes is testonly/constants.go:65-77.
func RootHashes() [][]byte {
	return [][]byte{
		EmptyRootHash(),
		hd("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
		hd("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
		hd("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"),
		hd("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
		hd("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4"),
		hd("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef"),
		hd("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"),
		hd("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"),
	}
}

// EmptyRootHash is testonly/constants.go:99-101.
func EmptyRootHash() []byte {
	return hd("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
}

// hd is testonly/constants.go:103-110.
func hd(b string) []byte {
	r, err := hex.DecodeString(b)
	if err != nil {
		panic(err)
	}
	return r
}

// ---------------------------------------------------------------------------
// rfc6962/rfc6962_test.go (v0.0.2), TestRFC6962Hasher, lines 26-59.
// The inputs are the arguments the test passes to the hasher; the wants are
// the literal strings.
// ---------------------------------------------------------------------------

type rfcHasherVector struct {
	desc  string
	kind  string // "empty", "leaf", "node"
	leaf  []byte
	left  []byte
	right []byte
	want  string
}

var rfc6962TestVectors = []rfcHasherVector{
	// rfc6962_test.go:34-39
	{desc: "RFC6962 Empty", kind: "empty", want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	// rfc6962_test.go:27,40-46: emptyLeafHash := hasher.HashLeaf([]byte{})
	{desc: "RFC6962 Empty Leaf", kind: "leaf", leaf: []byte{}, want: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
	// rfc6962_test.go:26,47-52: leafHash := hasher.HashLeaf([]byte("L123456"))
	{desc: "RFC6962 Leaf", kind: "leaf", leaf: []byte("L123456"), want: "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56"},
	// rfc6962_test.go:53-58: hasher.HashChildren([]byte("N123"), []byte("N456"))
	{desc: "RFC6962 Node", kind: "node", left: []byte("N123"), right: []byte("N456"), want: "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb"},
}

// ---------------------------------------------------------------------------
// proof/verify_test.go (v0.0.2)
// ---------------------------------------------------------------------------

// proof/verify_test.go:28-32
type inclusionProofTestVector struct {
	leaf  uint64
	size  uint64
	proof [][]byte
}

// proof/verify_test.go:40-66, 91-111 (consistencyProofs at 68-89 are not
// copied: consistency proofs are out of scope).
var (
	sha256SomeHash      = dh("abacaba000000000000000000000000000000000000000000060061e00123456", 32)
	sha256EmptyTreeHash = dh("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32)

	inclusionProofs = []inclusionProofTestVector{
		{0, 0, nil},
		{1, 1, nil},
		{1, 8, [][]byte{
			dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", 32),
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4", 32),
		}},
		{6, 8, [][]byte{
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32),
			dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", 32),
			dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		}},
		{3, 3, [][]byte{
			dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32),
		}},
		{2, 5, [][]byte{
			dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32),
			dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", 32),
			dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", 32),
		}},
	}

	roots = [][]byte{
		dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", 32),
		dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", 32),
		dh("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", 32),
		dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", 32),
		dh("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4", 32),
		dh("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", 32),
		dh("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c", 32),
		dh("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328", 32),
	}

	leaves = [][]byte{
		dh("", 0),
		dh("00", 1),
		dh("10", 1),
		dh("2021", 2),
		dh("3031", 2),
		dh("40414243", 4),
		dh("5051525354555657", 8),
		dh("606162636465666768696a6b6c6d6e6f", 16),
	}
)

// inclusionProbe is proof/verify_test.go:114-123.
type inclusionProbe struct {
	leafIndex uint64
	treeSize  uint64
	root      []byte
	leafHash  []byte
	proof     [][]byte

	desc string
}

// corruptInclusionProof is proof/verify_test.go:136-176, verbatim.
func corruptInclusionProof(leafIndex, treeSize uint64, proof [][]byte, root, leafHash []byte) []inclusionProbe {
	ret := []inclusionProbe{
		// Wrong leaf index.
		{leafIndex - 1, treeSize, root, leafHash, proof, "leafIndex - 1"},
		{leafIndex + 1, treeSize, root, leafHash, proof, "leafIndex + 1"},
		{leafIndex ^ 2, treeSize, root, leafHash, proof, "leafIndex ^ 2"},
		// Wrong tree height.
		{leafIndex, treeSize * 2, root, leafHash, proof, "treeSize * 2"},
		{leafIndex, treeSize / 2, root, leafHash, proof, "treeSize / 2"},
		// Wrong leaf or root.
		{leafIndex, treeSize, root, []byte("WrongLeaf"), proof, "wrong leaf"},
		{leafIndex, treeSize, sha256EmptyTreeHash, leafHash, proof, "empty root"},
		{leafIndex, treeSize, sha256SomeHash, leafHash, proof, "random root"},
		// Add garbage at the end.
		{leafIndex, treeSize, root, leafHash, extend(proof, []byte{}), "trailing garbage"},
		{leafIndex, treeSize, root, leafHash, extend(proof, root), "trailing root"},
		// Add garbage at the front.
		{leafIndex, treeSize, root, leafHash, prepend(proof, []byte{}), "preceding garbage"},
		{leafIndex, treeSize, root, leafHash, prepend(proof, root), "preceding root"},
	}
	ln := len(proof)

	// Modify single bit in an element of the proof.
	for i := 0; i < ln; i++ {
		wrongProof := prepend(proof)                          // Copy the proof slice.
		wrongProof[i] = append([]byte(nil), wrongProof[i]...) // But also the modified data.
		wrongProof[i][0] ^= 8                                 // Flip the bit.
		desc := fmt.Sprintf("modified proof[%d] bit 3", i)
		ret = append(ret, inclusionProbe{leafIndex, treeSize, root, leafHash, wrongProof, desc})
	}

	if ln > 0 {
		ret = append(ret, inclusionProbe{leafIndex, treeSize, root, leafHash, proof[:ln-1], "removed component"})
	}
	if ln > 1 {
		wrongProof := prepend(proof[1:], proof[0], sha256SomeHash)
		ret = append(ret, inclusionProbe{leafIndex, treeSize, root, leafHash, wrongProof, "inserted component"})
	}

	return ret
}

// singleEntryCases reproduces the table of TestVerifyInclusionSingleEntry,
// proof/verify_test.go:272-297. The test calls
// VerifyInclusion(hasher, 0, 1, tc.leaf, proof, tc.root) with an empty proof.
type singleEntryCase struct {
	root    []byte
	leaf    []byte
	wantErr bool
}

func singleEntryCases(h merkle.LogHasher) ([]byte, []singleEntryCase) {
	data := []byte("data")
	// Root and leaf hash for 1-entry tree are the same.
	hash := h.HashLeaf(data)
	emptyHash := []byte{}
	return hash, []singleEntryCase{
		{hash, hash, false},
		{hash, emptyHash, true},
		{emptyHash, hash, true},
		{emptyHash, emptyHash, true}, // Wrong hash size.
	}
}

// verifyInclusionProbes is the probe table of TestVerifyInclusion,
// proof/verify_test.go:302-304. For each probe the test asserts that these
// three calls (lines 307, 310, 313) all fail, with an empty proof:
//
//	VerifyInclusion(hasher, p.index, p.size, sha256SomeHash, proof, []byte{})
//	VerifyInclusion(hasher, p.index, p.size, []byte{}, proof, sha256EmptyTreeHash)
//	VerifyInclusion(hasher, p.index, p.size, sha256SomeHash, proof, sha256EmptyTreeHash)
var verifyInclusionProbes = []struct {
	index, size uint64
}{{0, 0}, {0, 1}, {1, 0}, {2, 1}}

// extend is proof/verify_test.go:384-389.
func extend(proof [][]byte, hashes ...[]byte) [][]byte {
	res := make([][]byte, len(proof), len(proof)+len(hashes))
	copy(res, proof)
	return append(res, hashes...)
}

// prepend is proof/verify_test.go:391-394.
func prepend(proof [][]byte, hashes ...[]byte) [][]byte {
	return append(hashes, proof...)
}

// dh is proof/verify_test.go:396-405.
func dh(h string, expLen int) []byte {
	r, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	if got := len(r); got != expLen {
		panic(fmt.Sprintf("decode %q: len=%d, want %d", h, got, expLen))
	}
	return r
}

// ---------------------------------------------------------------------------
// testonly/reference_test.go (v0.0.2)
// ---------------------------------------------------------------------------

// refRootHash is testonly/reference_test.go:36-47, verbatim.
func refRootHash(entries [][]byte, hasher merkle.LogHasher) []byte {
	if len(entries) == 0 {
		return hasher.EmptyRoot()
	}
	if len(entries) == 1 {
		return hasher.HashLeaf(entries[0])
	}
	split := downToPowerOfTwo(uint64(len(entries)))
	return hasher.HashChildren(
		refRootHash(entries[:split], hasher),
		refRootHash(entries[split:], hasher))
}

// refInclusionProof is testonly/reference_test.go:52-66, verbatim.
func refInclusionProof(entries [][]byte, index uint64, hasher merkle.LogHasher) [][]byte {
	size := uint64(len(entries))
	if size == 1 || index >= size {
		return nil
	}
	split := downToPowerOfTwo(size)
	if index < split {
		return append(
			refInclusionProof(entries[:split], index, hasher),
			refRootHash(entries[split:], hasher))
	}
	return append(
		refInclusionProof(entries[split:], index-split, hasher),
		refRootHash(entries[:split], hasher))
}

// downToPowerOfTwo is testonly/reference_test.go:105-111, verbatim.
func downToPowerOfTwo(x uint64) uint64 {
	if x < 2 {
		panic("downToPowerOfTwo requires value >= 2")
	}
	return uint64(1) << (bits.Len64(x-1) - 1)
}

// refInclusionProofVectors is the table of TestRefInclusionProof,
// testonly/reference_test.go:124-154. The test builds each expected path
// with refInclusionProof(LeafInputs()[:size], index, ...) (line 157).
var refInclusionProofVectors = []struct {
	index uint64
	size  uint64
	want  [][]byte
}{
	{index: 0, size: 1, want: nil},
	{index: 0, size: 2, want: [][]byte{
		hd("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
	}},
	{index: 1, size: 2, want: [][]byte{
		hd("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
	}},
	{index: 2, size: 3, want: [][]byte{
		hd("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"),
	}},
	{index: 1, size: 5, want: [][]byte{
		hd("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
		hd("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
		hd("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
	}},
	{index: 0, size: 8, want: [][]byte{
		hd("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"),
		hd("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
		hd("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"),
	}},
	{index: 5, size: 8, want: [][]byte{
		hd("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"),
		hd("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
		hd("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"),
	}},
}

// ---------------------------------------------------------------------------
// compact/range_test.go (v0.0.2), TestGetRootHashGolden, lines 411-469.
// Hashes are standard base64, as upstream writes them. Leaf i's data is
// []byte{byte(i & 0xff), byte((i >> 8) & 0xff)} (line 472), hashed with
// rfc6962 HashLeaf (hashLeaf, lines 596-598). The fixture states it as
// leaf_data_rule "u16le" (2 bytes little-endian), which build.go and
// check.go compare with goldenLeafData for every leaf.
// ---------------------------------------------------------------------------

type goldenNode struct {
	level uint
	index uint64
	hash  string
}

var getRootHashGolden = []struct {
	size      int
	wantRoot  string
	wantNodes []goldenNode
}{
	{size: 0, wantRoot: "", wantNodes: []goldenNode{}}, // TODO(pavelkalinnikov): Use hasher.EmptyRoot().
	{
		size:      10,
		wantRoot:  "VjWMPSYNtCuCNlF/RLnQy6HcwSk6CIipfxm+hettA+4=",
		wantNodes: []goldenNode{{4, 0, "VjWMPSYNtCuCNlF/RLnQy6HcwSk6CIipfxm+hettA+4="}},
	},
	{size: 15, wantRoot: "j4SulYmocFuxdeyp12xXCIgK6PekBcxzAIj4zbQzNEI="},
	{size: 16, wantRoot: "c+4Uc6BCMOZf/v3NZK1kqTUJe+bBoFtOhP+P3SayKRE=", wantNodes: []goldenNode{}},
	{
		size:     100,
		wantRoot: "dUh9hYH88p0CMoHkdr1wC2szbhcLAXOejWpINIooKUY=",
		wantNodes: []goldenNode{
			{6, 1, "/K5I3bQ6Wz/beVi9IFKizZ073WqI8kGqstdkbmMcTXI="},
			{7, 0, "dUh9hYH88p0CMoHkdr1wC2szbhcLAXOejWpINIooKUY="},
		},
	},
	{
		size:     255,
		wantRoot: "SmdsuKUqiod3RX2jyF2M6JnbdE4QuTwwipfAowI4/i0=",
		wantNodes: []goldenNode{
			{2, 63, "EphrHrAU2E+H65CW1o2SwiJVA1dNragVhsMsOkyBdZ4="},
			{3, 31, "fwen9eGNKOdGYC7L1GSwMKBlyjIIZBlsKVkmPGtsZEY="},
			{4, 15, "Iq5blg5fdl93qbEUzBBEiGMoP7zyzbwf14JuB5YBidM="},
			{5, 7, "D6s+gn79wNsgmdvBv0fVIYCougsU+PUSdtLGrWGmyO4="},
			{6, 3, "swSuozoE2E7iTV9cnNGcnjbLEeDq+5ep2hRJuI0pTtI="},
			{7, 1, "xv1RcZ3JpQusUjlsGQzsV9kWuITo3aLNpEsKymbFhak="},
			{8, 0, "SmdsuKUqiod3RX2jyF2M6JnbdE4QuTwwipfAowI4/i0="},
		},
	},
	{size: 256, wantRoot: "qFI0t/tZ1MdOYgyPpPzHFiZVw86koScXy9q3FU5casA=", wantNodes: []goldenNode{}},
	{
		size:     1000,
		wantRoot: "RXrgb8xHd55Y48FbfotJwCbV82Kx22LZfEbmBGAvwlQ=",
		wantNodes: []goldenNode{
			{6, 15, "CBbiN/le+CpZNxEmCVIgfQSl/ZTapYxUOsdKTkiVjtc="},
			{7, 7, "npfCeOdllUJZLLRbvEkxlwY7enS6pRlChKVTJjHcevI="},
			{8, 3, "5MVDHIWhLErkcLgceSnxZWOTG04QlhIkm3aUEOQLpWw="},
			{9, 1, "6EoN2SheMl5oA3qymXw1Ltcp1ku/INU+rBqEe2+jIjI="},
			{10, 0, "RXrgb8xHd55Y48FbfotJwCbV82Kx22LZfEbmBGAvwlQ="},
		},
	},
	{size: 4095, wantRoot: "cWRFdQhPcjn9WyBXE/r1f04ejxIm5lvg40DEpRBVS0w="},
	{size: 4096, wantRoot: "6uU/phfHg1n/GksYT6TO9aN8EauMCCJRl3dIK0HDs2M=", wantNodes: []goldenNode{}},
	{size: 10000, wantRoot: "VZcav65F9haHVRk3wre2axFoBXRNeUh/1d9d5FQfxIg="},
	{size: 65535, wantRoot: "iPuVYJhP6SEE4gUFp8qbafd2rYv9YTCDYqAxCj8HdLM="},
}

// goldenLeafData is the leaf data scheme of compact/range_test.go:472.
func goldenLeafData(i int) []byte {
	return []byte{byte(i & 0xff), byte((i >> 8) & 0xff)}
}

// ---------------------------------------------------------------------------
// proof/proof_test.go (v0.0.2), TestInclusion, lines 47-131.
// The table at lines 55-113 is copied character for character, with one
// substitution: upstream builds proof.Nodes, whose begin and end fields are
// unexported and cannot be set outside package proof, so the copy builds the
// local type inclusionShape (same fields: IDs, begin, end) instead of Nodes,
// through the same id/nodes/rehash closures (lines 48-54). Upstream asserts
// proof.Inclusion(index, size) returns an error for the wantErr rows and
// exactly these IDs, begin and end otherwise (lines 114-129, the ephemeral
// node ID is ignored there); check.go reruns that assertion. The IDs are
// node coordinates only, no hashes: build.go materializes them over
// genEntries leaf data.
// ---------------------------------------------------------------------------

type inclusionShape struct {
	IDs        []compact.NodeID
	begin, end int
}

type proofInclusionCase struct {
	size    uint64 // The requested past tree size.
	index   uint64 // Leaf index in the requested tree.
	want    inclusionShape
	wantErr bool
}

func proofTestInclusionCases() []proofInclusionCase {
	id := compact.NewNodeID
	nodes := func(ids ...compact.NodeID) inclusionShape {
		return inclusionShape{IDs: ids}
	}
	rehash := func(begin, end int, ids ...compact.NodeID) inclusionShape {
		return inclusionShape{IDs: ids, begin: begin, end: end}
	}
	return []proofInclusionCase{
		// Errors.
		{size: 0, index: 0, wantErr: true},
		{size: 0, index: 1, wantErr: true},
		{size: 1, index: 2, wantErr: true},
		{size: 0, index: 3, wantErr: true},
		{size: 7, index: 8, wantErr: true},

		// Small trees.
		{size: 1, index: 0, want: inclusionShape{IDs: []compact.NodeID{}}},
		{size: 2, index: 0, want: nodes(id(0, 1))},                  // b
		{size: 2, index: 1, want: nodes(id(0, 0))},                  // a
		{size: 3, index: 1, want: rehash(1, 2, id(0, 0), id(0, 2))}, // a c

		// Tree of size 7.
		{size: 7, index: 0, want: rehash(2, 4, // l=hash(i,j)
			id(0, 1), id(1, 1), id(0, 6), id(1, 2))}, // b h j i
		{size: 7, index: 1, want: rehash(2, 4, // l=hash(i,j)
			id(0, 0), id(1, 1), id(0, 6), id(1, 2))}, // a h j i
		{size: 7, index: 2, want: rehash(2, 4, // l=hash(i,j)
			id(0, 3), id(1, 0), id(0, 6), id(1, 2))}, // d g j i
		{size: 7, index: 3, want: rehash(2, 4, // l=hash(i,j)
			id(0, 2), id(1, 0), id(0, 6), id(1, 2))}, // c g j i
		{size: 7, index: 4, want: rehash(1, 2, id(0, 5), id(0, 6), id(2, 0))}, // f j k
		{size: 7, index: 5, want: rehash(1, 2, id(0, 4), id(0, 6), id(2, 0))}, // e j k
		{size: 7, index: 6, want: nodes(id(1, 2), id(2, 0))},                  // i k

		// Smaller trees within a bigger stored tree.
		{size: 4, index: 2, want: nodes(id(0, 3), id(1, 0))},                  // d g
		{size: 5, index: 3, want: rehash(2, 3, id(0, 2), id(1, 0), id(0, 4))}, // c g e
		{size: 6, index: 3, want: rehash(2, 3, id(0, 2), id(1, 0), id(1, 2))}, // c g i
		{size: 6, index: 4, want: nodes(id(0, 5), id(2, 0))},                  // f k
		{size: 7, index: 1, want: rehash(2, 4, // l=hash(i,j)
			id(0, 0), id(1, 1), id(0, 6), id(1, 2))}, // a h j i
		{size: 7, index: 3, want: rehash(2, 4, // l=hash(i,j)
			id(0, 2), id(1, 0), id(0, 6), id(1, 2))}, // c g j i

		// Some rehashes in the middle of the returned list.
		{size: 15, index: 10, want: rehash(2, 4,
			id(0, 11), id(1, 4),
			id(0, 14), id(1, 6),
			id(3, 0),
		)},
		{size: 31, index: 24, want: rehash(2, 4,
			id(0, 25), id(1, 13),
			id(0, 30), id(1, 14),
			id(3, 2), id(4, 0),
		)},
		{size: 95, index: 81, want: rehash(3, 6,
			id(0, 80), id(1, 41), id(2, 21),
			id(0, 94), id(1, 46), id(2, 22),
			id(4, 4), id(6, 0),
		)},
	}
}

// ---------------------------------------------------------------------------
// testonly/tree_test.go (v0.0.2)
// ---------------------------------------------------------------------------

// genEntries is testonly/tree_test.go:196-203, verbatim. Used only for the
// "generated:" cases.
func genEntries(size uint64) [][]byte {
	entries := make([][]byte, size)
	for i := range entries {
		entries[i] = []byte(strconv.Itoa(i))
	}
	return entries
}
