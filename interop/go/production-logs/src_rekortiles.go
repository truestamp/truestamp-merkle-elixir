// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains literals copied from github.com/sigstore/rekor-tiles@v0.1.11
// pkg/verify/verify_test.go (Apache-2.0). License text: LICENSE-rekor-tiles;
// see NOTICE.

package main

// Rekor v2's own inclusion-proof test, TestVerifyInclusionProof in
// github.com/sigstore/rekor-tiles@v0.1.11 pkg/verify/verify_test.go:32-110. It
// reuses rekor v1's two-entry log (src_rekor.go). rekor-tiles
// pkg/verify/verify.go:30-40 VerifyInclusionProof computes the leaf as rfc6962
// HashLeaf(entry.CanonicalizedBody) and calls transparency-dev/merkle
// proof.VerifyInclusion with the entry's LogIndex (the test sets it to 1 at
// verify_test.go:99), the checkpoint's Size (the test's logSize) and the
// checkpoint's Hash (rootHash, verify_test.go:95). The InclusionProof's own
// LogIndex and TreeSize are not read.

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/transparency-dev/merkle/rfc6962"
)

// Copied verbatim from github.com/sigstore/rekor-tiles@v0.1.11
// pkg/verify/verify_test.go:33 (hash), :34 (rootHash), :35 (body) and :61 (the
// 'invalid hash' case's proof hash), Apache-2.0.
var (
	rekorTilesHash        = []byte{89, 165, 117, 241, 87, 39, 71, 2, 195, 141, 227, 171, 30, 23, 132, 34, 111, 57, 31, 183, 149, 0, 235, 249, 240, 43, 68, 57, 251, 119, 87, 76}
	rekorTilesRootHash    = []byte{91, 225, 117, 141, 210, 34, 138, 207, 175, 37, 70, 180, 182, 206, 138, 164, 12, 130, 163, 116, 143, 61, 203, 85, 14, 13, 103, 186, 52, 240, 42, 69}
	rekorTilesBody        = []byte("{\"apiVersion\":\"0.0.1\",\"kind\":\"rekord\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8\"}},\"signature\":{\"content\":\"MEYCIQD/PdPQmKWC1+0BNEd5gKvQGr1xxl3ieUffv3jk1zzJKwIhALBj3xfAyWxlz4jpoIEIV1UfK9vnkUUOSoeZxBZPHKPC\",\"format\":\"x509\",\"publicKey\":{\"content\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTU9jVGZSQlM5amlYTTgxRlo4Z20vMStvbWVNdwptbi8zNDcvNTU2Zy9scmlTNzJ1TWhZOUxjVCs1VUo2ZkdCZ2xyNVo4TDBKTlN1YXN5ZWQ5T3RhUnZ3PT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==\"}}}}")
	rekorTilesInvalidHash = []byte{0, 165, 117, 241, 87, 39, 71, 2, 195, 141, 227, 171, 30, 23, 132, 34, 111, 57, 31, 183, 149, 0, 235, 249, 240, 43, 68, 57, 251, 119, 87, 76}
)

// The four cases of TestVerifyInclusionProof (verify_test.go:43-90): name,
// source lines, the checkpoint size (logSize), the proof hashes and wantErr.
// Every case has InclusionProof LogIndex 1 and TreeSize 2, which
// VerifyInclusionProof does not read, and entry LogIndex 1 (line 99).
var rekorTilesCases = []struct {
	name    string
	lines   string
	logSize uint64
	hashes  [][]byte
	wantErr bool
}{
	{"valid inclusionproof", "43-54", 2, [][]byte{rekorTilesHash}, false},
	{"invalid hash", "55-66", 2, [][]byte{rekorTilesInvalidHash}, true},
	{"inclusion index beyond log size", "67-78", 1, [][]byte{rekorTilesHash}, true},
	{"wrong proof size", "79-90", 3, [][]byte{rekorTilesHash}, true},
}

const rekorTilesEntryLogIndex = 1 // verify_test.go:99

func (b *builder) rekorTiles() {
	h := rfc6962.DefaultHasher
	v1Body, err := base64.StdEncoding.DecodeString(rekorValidBody)
	b.expect(err == nil && bytes.Equal(rekorTilesBody, v1Body), "rekor-tiles body is not rekor v1.5.4's 'valid inclusion' body")
	b.expect(bytes.Equal(rekorTilesHash, mustHex(rekorRoot1)), "rekor-tiles hash is not rekor v1.5.4 TestConsistency root1")
	b.expect(bytes.Equal(rekorTilesRootHash, mustHex(rekorRoot2)), "rekor-tiles rootHash is not rekor v1.5.4 TestConsistency root2")
	b.expect(len(rekorTilesInvalidHash) == 32 && rekorTilesInvalidHash[0] == 0 && rekorTilesHash[0] == 0x59 && bytes.Equal(rekorTilesInvalidHash[1:], rekorTilesHash[1:]),
		"rekor-tiles 'invalid hash' is not hash with its first byte 0x59 changed to 0x00")
	leaf := h.HashLeaf(rekorTilesBody)
	b.expect(bytes.Equal(leaf, mustHex(rekorConsHash)) && bytes.Equal(leaf, refLeaf(rekorTilesBody)), "rekor-tiles leaf is not the rekor v1.5.4 entry 1 leaf hash")
	for _, c := range rekorTilesCases {
		exp := "valid"
		if c.wantErr {
			exp = "invalid"
		}
		inc := Inclusion{
			Name: fmt.Sprintf("rekor-tiles v0.1.11 pkg/verify/verify_test.go:%s TestVerifyInclusionProof '%s' (wantErr %v): entry LogIndex 1 (line 99), checkpoint size %d (logSize), root = rootHash (line 34), leaf = HashLeaf(body line 35), %d hash(es) (rekor v1's two-entry log)",
				c.lines, c.name, c.wantErr, c.logSize, len(c.hashes)),
			LeafHash:            hx(leaf),
			LeafIndex:           rekorTilesEntryLogIndex,
			TreeSize:            c.logSize,
			Path:                hxs(c.hashes),
			Root:                hx(rekorTilesRootHash),
			UpstreamExpectation: exp,
		}
		b.addPublishedDedup(inc)
	}
}
