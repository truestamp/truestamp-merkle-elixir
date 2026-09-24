// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains code copied byte for byte from
// github.com/google/certificate-transparency-go@v1.0.16 (Apache-2.0, Copyright
// 2015 and 2016 Google Inc. All Rights Reserved.): merkletree/tree_hasher_test.go
// lines 24-69, merkletree/merkle_verifier_test.go lines 30-119, 219-319, 322-349
// and 353-401, and serialization_test.go line 383. License:
// LICENSE-certificate-transparency-go in this directory. Changes: the copied
// lines are unmodified; the lines outside the markers are ours.

package main

// Every block that follows a "BEGIN <file>:<first>-<last>" marker holds
// exactly those lines of the upstream file, byte for byte; an "END" marker
// follows it, after any blank lines gofmt requires. Each block is compared at
// run time with those lines of the module's own file, vendored byte for byte
// under testdata/certificate-transparency-go@v1.0.16/ with its SHA-256 pinned
// in main.go, and the program fails if a single byte differs. Only the lines
// outside the blocks are ours: the upstream test functions take *testing.T, so
// their bodies are wrapped in functions that take a *fakeT with the same
// Fatal/Fatalf methods, and getVerifier/MerkleVerifier are supplied by main.go
// (a recording wrapper around the module's merkletree.MerkleVerifier).

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

// BEGIN merkletree/tree_hasher_test.go:24-69
type leafTestVector struct {
	inputLength int64
	input       []byte
	output      []byte
}

// Inputs and outputs are of fixed digest size.
type nodeTestVector struct {
	left   []byte
	right  []byte
	output []byte
}

type testVector struct {
	emptyHash []byte
	leaves    []leafTestVector
	nodes     []nodeTestVector
}

const (
	sha256EmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func dh(h string) []byte {
	r, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return r
}

func getTestVector() testVector {
	return testVector{
		emptyHash: dh(sha256EmptyHash),
		leaves: []leafTestVector{
			{0, dh(""), dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")},
			{1, dh("00"), dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7")},
			{16, dh("101112131415161718191a1b1c1d1e1f"), dh("3bfb960453ebaebf33727da7a1f4db38acc051d381b6da20d6d4e88f0eabfd7a")},
		},
		nodes: []nodeTestVector{
			{dh("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
				dh("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
				dh("1a378704c17da31e2d05b6d121c2bb2c7d76f6ee6fa8f983e596c2d034963c57")},
		},
	}
}

// END

// BEGIN merkletree/merkle_verifier_test.go:30-119
const (
	sha256EmptyTreeHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func verifierCheck(v *MerkleVerifier, leafIndex, treeSize int64, proof [][]byte, root []byte, leaf []byte) error {
	// Verify original inclusion proof
	got, err := v.RootFromInclusionProof(leafIndex, treeSize, proof, leaf)
	if err != nil {
		return err
	}
	if want := root; !bytes.Equal(got, want) {
		return fmt.Errorf("got root:\n%x\nexpected:\n%x", got, want)
	}
	if err := v.VerifyInclusionProof(leafIndex, treeSize, proof, root, leaf); err != nil {
		return err
	}

	// Wrong leaf index
	if err := v.VerifyInclusionProof(leafIndex-1, treeSize, proof, root, leaf); err == nil {
		return errors.New("incorrectly verified against leafIndex - 1")
	}
	if err := v.VerifyInclusionProof(leafIndex+1, treeSize, proof, root, leaf); err == nil {
		return errors.New("incorrectly verified against leafIndex + 1")
	}
	if err := v.VerifyInclusionProof(leafIndex^2, treeSize, proof, root, leaf); err == nil {
		return errors.New("incorrectly verified against leafIndex ^ 2")
	}

	// Wrong tree height
	if err := v.VerifyInclusionProof(leafIndex, treeSize*2, proof, root, leaf); err == nil {
		return errors.New("incorrectly verified against treeSize * 2")
	}
	if err := v.VerifyInclusionProof(leafIndex, treeSize/2, proof, root, leaf); err == nil {
		return errors.New("incorrectly verified against treeSize / 2")
	}

	// Wrong leaf
	if err := v.VerifyInclusionProof(leafIndex, treeSize, proof, root, []byte("WrongLeaf")); err == nil {
		return errors.New("incorrectly verified against WrongLeaf")
	}

	// Wrong root
	if err := v.VerifyInclusionProof(leafIndex, treeSize, proof, dh(sha256EmptyTreeHash), leaf); err == nil {
		return errors.New("incorrectly verified against empty root hash")
	}

	// Wrong inclusion proofs

	// Modify single element of the proof
	for i := 0; i < len(proof); i++ {
		tmp := proof[i]
		proof[i] = dh(sha256EmptyTreeHash)
		if err := v.VerifyInclusionProof(leafIndex, treeSize, proof, root, leaf); err == nil {
			return errors.New("incorrectly verified against incorrect inclusion proof")
		}
		proof[i] = tmp
	}

	// Add garbage at the end
	wrongProof := append(proof, []byte(""))
	if err := v.VerifyInclusionProof(leafIndex, treeSize, wrongProof, root, leaf); err == nil {
		return errors.New("incorrectly verified against proof with trailing garbage")
	}

	wrongProof = append(proof, root)
	if err := v.VerifyInclusionProof(leafIndex, treeSize, wrongProof, root, leaf); err == nil {
		return errors.New("incorrectly verified against proof with trailing root")
	}

	if len(proof) > 0 {
		// Remove a node from the end
		wrongProof = proof[:len(proof)-1]
		if err := v.VerifyInclusionProof(leafIndex, treeSize, wrongProof, root, leaf); err == nil {
			return errors.New("incorrectly verified against truncated proof")
		}
	}

	// Add garbage at the front
	wrongProof = append([][]byte{{}}, proof...)
	if err := v.VerifyInclusionProof(leafIndex, treeSize, wrongProof, root, leaf); err == nil {
		return errors.New("incorrectly verified against proof with preceding garbage")
	}

	wrongProof = append([][]byte{root}, proof...)
	if err := v.VerifyInclusionProof(leafIndex, treeSize, wrongProof, root, leaf); err == nil {
		return errors.New("incorrectly verified against proof with preceding garbage")
	}

	return nil
}

// END

// BEGIN merkletree/merkle_verifier_test.go:219-319
type proofTestVector struct {
	h []byte
	l int
}

type inclusionProofTestVector struct {
	leaf, snapshot, proofLength int64
	proof                       []proofTestVector
}

func getInputs() []proofTestVector {
	return []proofTestVector{
		{dh(""), 0},
		{dh("00"), 1},
		{dh("10"), 1},
		{dh("2021"), 2},
		{dh("3031"), 2},
		{dh("40414243"), 4},
		{dh("5051525354555657"), 8},
		{dh("606162636465666768696a6b6c6d6e6f"), 16},
	}
}

func getInclusionTestVector() []inclusionProofTestVector {
	return []inclusionProofTestVector{
		{0, 0, 0, []proofTestVector{{dh(""), 0}, {dh(""), 0}, {dh(""), 0}}},
		{1, 1, 0, []proofTestVector{{dh(""), 0}, {dh(""), 0}, {dh(""), 0}}},
		{1,
			8,
			3,
			[]proofTestVector{
				{dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"), 32},
				{dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"), 32},
				{dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"), 32}}},
		{6,
			8,
			3,
			[]proofTestVector{
				{dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"), 32},
				{dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"), 32},
				{dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"), 32}}},
		{3,
			3,
			1,
			[]proofTestVector{
				{dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"), 32},
				{dh(""), 0},
				{dh(""), 0}}},
		{2,
			5,
			3,
			[]proofTestVector{
				{dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"), 32},
				{dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"), 32},
				{dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"), 32}},
		}}
}

func getRoots() []proofTestVector {
	return []proofTestVector{
		{dh("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"), 32},
		{dh("fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"), 32},
		{dh("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77"), 32},
		{dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"), 32},
		{dh("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4"), 32},
		{dh("76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef"), 32},
		{dh("ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c"), 32},
		{dh("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"), 32}}
}

type consistencyTestVector struct {
	snapshot1, snapshot2, proofLen int64
	proof                          [3]proofTestVector
}

func getConsistencyProofs() []consistencyTestVector {
	return []consistencyTestVector{
		{1, 1, 0, [3]proofTestVector{{dh(""), 0}, {dh(""), 0}, {dh(""), 0}}},
		{1,
			8,
			3,
			[3]proofTestVector{
				{dh("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"), 32},
				{dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"), 32},
				{dh("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"), 32}}},
		{6,
			8,
			3,
			[3]proofTestVector{
				{dh("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a"), 32},
				{dh("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"), 32},
				{dh("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"), 32}}},
		{2,
			5,
			2,
			[3]proofTestVector{
				{dh("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"), 32},
				{dh("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"), 32},
				{dh(""), 0}}},
	}
}

// END

// testVerifyInclusionProofTreeSizeOne is the body of TestVerifyInclusionProofTreeSizeOne
// (merkletree/merkle_verifier_test.go:321-350). It reads ../testdata relative to
// the module's merkletree directory, so main.go runs it from the vendored copy
// of that directory.
func testVerifyInclusionProofTreeSizeOne(t *fakeT) {
	// BEGIN merkletree/merkle_verifier_test.go:322-349
	v := getVerifier()
	// Serialized MerkleTreeLeaf from test-cert.pem and test-cert.proof
	certFile := "../testdata/test-cert.pem"
	sctFile := "../testdata/test-cert.proof"
	certB, err := ioutil.ReadFile(certFile)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", certFile, err)
	}
	certDER, _ := pem.Decode(certB)

	sctB, err := ioutil.ReadFile(sctFile)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", sctFile, err)
	}
	var sct ct.SignedCertificateTimestamp
	if _, err := tls.Unmarshal(sctB, &sct); err != nil {
		t.Fatalf("Failed to deserialize sct: %v", err)
	}

	leaf := ct.CreateX509MerkleTreeLeaf(ct.ASN1Cert{Data: certDER.Bytes}, sct.Timestamp)
	data, err := tls.Marshal(*leaf)
	if err != nil {
		t.Fatalf("Failed to serialize x509 leaf: %v", err)
	}
	// Test output from a real CT instance.
	if err := verifierCheck(&v, 0, 1, [][]byte{}, dh("04a64b64631b0270d6d204168cd24d0b24b6220c1e5a7efa616ded165bb702e6"), data); err != nil {
		t.Fatalf("i=%s: %s", "test-cert", err)
	}
	// END
}

// testVerifyInclusionProof is the body of TestVerifyInclusionProof
// (merkletree/merkle_verifier_test.go:352-402).
func testVerifyInclusionProof(t *fakeT) {
	// BEGIN merkletree/merkle_verifier_test.go:353-401
	v := getVerifier()
	path := [][]byte{}
	// Various invalid paths
	if err := v.VerifyInclusionProof(0, 0, path, []byte{}, []byte{}); err == nil {
		t.Fatal("Incorrectly verified invalid path 1")
	}
	if err := v.VerifyInclusionProof(0, 1, path, []byte{}, []byte{}); err == nil {
		t.Fatal("Incorrectly verified invalid path 2")
	}
	if err := v.VerifyInclusionProof(1, 0, path, []byte{}, []byte{}); err == nil {
		t.Fatal("Incorrectly verified invalid path 3")
	}
	if err := v.VerifyInclusionProof(2, 1, path, []byte{}, []byte{}); err == nil {
		t.Fatal("Incorrectly verified invalid path 4")
	}

	if err := v.VerifyInclusionProof(0, 0, path, dh(sha256EmptyTreeHash), []byte{}); err == nil {
		t.Fatal("Incorrectly verified invalid root 1")
	}
	if err := v.VerifyInclusionProof(0, 1, path, dh(sha256EmptyTreeHash), []byte{}); err == nil {
		t.Fatal("Incorrectly verified invalid root 2")
	}
	if err := v.VerifyInclusionProof(1, 0, path, dh(sha256EmptyTreeHash), []byte{}); err == nil {
		t.Fatal("Incorrectly verified invalid root 3")
	}
	if err := v.VerifyInclusionProof(2, 1, path, dh(sha256EmptyTreeHash), []byte{}); err == nil {
		t.Fatal("Incorrectly verified invalid root 4")
	}

	// Known good paths.

	inclusionProofs := getInclusionTestVector()
	inputs := getInputs()
	roots := getRoots()
	// i = 0 is an invalid path.
	for i := 1; i < 6; i++ {
		// Construct the path.
		proof := [][]byte{}
		for j := int64(0); j < inclusionProofs[i].proofLength; j++ {
			proof = append(proof, inclusionProofs[i].proof[j].h)
		}
		err := verifierCheck(&v, inclusionProofs[i].leaf-1, inclusionProofs[i].snapshot, proof,
			roots[inclusionProofs[i].snapshot-1].h,
			inputs[inclusionProofs[i].leaf-1].h)
		if err != nil {
			t.Fatalf("i=%d: %s", i, err)
		}
	}

	// END
}

// upstreamTestCertLeafBytes returns the serialized X509 MerkleTreeLeaf for
// testdata/test-cert.pem that TestX509MerkleTreeLeafHash (serialization_test.go:359-388)
// hard-codes; it is the leaf behind the size-1 tree of TestVerifyInclusionProofTreeSizeOne.
func upstreamTestCertLeafBytes() []byte {
	// BEGIN serialization_test.go:383-383
	leafBytes := dh("00000000013ddb27ded900000002ce308202ca30820233a003020102020106300d06092a864886f70d01010505003055310b300906035504061302474231243022060355040a131b4365727469666963617465205472616e73706172656e6379204341310e300c0603550408130557616c65733110300e060355040713074572772057656e301e170d3132303630313030303030305a170d3232303630313030303030305a3052310b30090603550406130247423121301f060355040a13184365727469666963617465205472616e73706172656e6379310e300c0603550408130557616c65733110300e060355040713074572772057656e30819f300d06092a864886f70d010101050003818d0030818902818100b1fa37936111f8792da2081c3fe41925008531dc7f2c657bd9e1de4704160b4c9f19d54ada4470404c1c51341b8f1f7538dddd28d9aca48369fc5646ddcc7617f8168aae5b41d43331fca2dadfc804d57208949061f9eef902ca47ce88c644e000f06eeeccabdc9dd2f68a22ccb09dc76e0dbc73527765b1a37a8c676253dcc10203010001a381ac3081a9301d0603551d0e041604146a0d982a3b62c44b6d2ef4e9bb7a01aa9cb798e2307d0603551d230476307480145f9d880dc873e654d4f80dd8e6b0c124b447c355a159a4573055310b300906035504061302474231243022060355040a131b4365727469666963617465205472616e73706172656e6379204341310e300c0603550408130557616c65733110300e060355040713074572772057656e82010030090603551d1304023000300d06092a864886f70d010105050003818100171cd84aac414a9a030f22aac8f688b081b2709b848b4e5511406cd707fed028597a9faefc2eee2978d633aaac14ed3235197da87e0f71b8875f1ac9e78b281749ddedd007e3ecf50645f8cbf667256cd6a1647b5e13203bb8582de7d6696f656d1c60b95f456b7fcf338571908f1c69727d24c4fccd249295795814d1dac0e60000")
	// END
	return leafBytes
}
