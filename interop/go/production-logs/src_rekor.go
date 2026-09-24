// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains literals copied from github.com/sigstore/rekor@v1.5.4
// pkg/verify/verify_test.go (Apache-2.0). License text: LICENSE-rekor; see
// NOTICE.

package main

// Rekor's own hard-coded two-entry log, from github.com/sigstore/rekor@v1.5.4
// pkg/verify/verify_test.go (Apache-2.0). rekor pkg/verify/verify.go:137-177
// VerifyInclusion computes the leaf as rfc6962 HashLeaf(base64-decoded body)
// and calls transparency-dev/merkle proof.VerifyInclusion.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// Copied verbatim from github.com/sigstore/rekor@v1.5.4 pkg/verify/verify_test.go:67-71
// (TestConsistency), Apache-2.0.
const (
	rekorRoot2    = "5be1758dd2228acfaf2546b4b6ce8aa40c82a3748f3dcb550e0d67ba34f02a45"
	rekorRoot1    = "59a575f157274702c38de3ab1e1784226f391fb79500ebf9f02b4439fb77574c"
	rekorRoot0    = "1a341bc342ff4e567387de9789ab14000b147124317841489172419874198147"
	rekorConsHash = "d3be742c8d73e2dd3c5635843e987ad3dfb3837616f412a07bf730c3ad73f5cb"
)

// Copied verbatim from github.com/sigstore/rekor@v1.5.4 pkg/verify/verify_test.go:189-238
// (TestInclusion), Apache-2.0: the "valid inclusion" body (line 200), the
// "invalid inclusion - bad body hash" body (line 221, first character e -> a),
// and the proof both cases share (lines 203-211 and 224-232).
const (
	rekorValidBody = "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJlY2RjNTUzNmY3M2JkYWU4ODE2ZjBlYTQwNzI2ZWY1ZTliODEwZDkxNDQ5MzA3NTkwM2JiOTA2MjNkOTdiMWQ4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQvUGRQUW1LV0MxKzBCTkVkNWdLdlFHcjF4eGwzaWVVZmZ2M2prMXp6Skt3SWhBTEJqM3hmQXlXeGx6NGpwb0lFSVYxVWZLOXZua1VVT1NvZVp4QlpQSEtQQyIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRlRVOWpWR1pTUWxNNWFtbFlUVGd4UmxvNFoyMHZNU3R2YldWTmR3cHRiaTh6TkRjdk5UVTJaeTlzY21sVE56SjFUV2haT1V4alZDczFWVW8yWmtkQ1oyeHlOVm80VERCS1RsTjFZWE41WldRNVQzUmhVblozUFQwS0xTMHRMUzFGVGtRZ1VGVkNURWxESUV0RldTMHRMUzB0Q2c9PSJ9fX19"
	rekorBadBody   = "ayJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJlY2RjNTUzNmY3M2JkYWU4ODE2ZjBlYTQwNzI2ZWY1ZTliODEwZDkxNDQ5MzA3NTkwM2JiOTA2MjNkOTdiMWQ4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FWUNJUUQvUGRQUW1LV0MxKzBCTkVkNWdLdlFHcjF4eGwzaWVVZmZ2M2prMXp6Skt3SWhBTEJqM3hmQXlXeGx6NGpwb0lFSVYxVWZLOXZua1VVT1NvZVp4QlpQSEtQQyIsImZvcm1hdCI6Ing1MDkiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6IkxTMHRMUzFDUlVkSlRpQlFWVUpNU1VNZ1MwVlpMUzB0TFMwS1RVWnJkMFYzV1VoTGIxcEplbW93UTBGUldVbExiMXBKZW1vd1JFRlJZMFJSWjBGRlRVOWpWR1pTUWxNNWFtbFlUVGd4UmxvNFoyMHZNU3R2YldWTmR3cHRiaTh6TkRjdk5UVTJaeTlzY21sVE56SjFUV2haT1V4alZDczFWVW8yWmtkQ1oyeHlOVm80VERCS1RsTjFZWE41WldRNVQzUmhVblozUFQwS0xTMHRMUzFGVGtRZ1VGVkNURWxESUV0RldTMHRMUzB0Q2c9PSJ9fX19"
	rekorLogIndex  = 1
	rekorTreeSize  = 2
	rekorRootHash  = "5be1758dd2228acfaf2546b4b6ce8aa40c82a3748f3dcb550e0d67ba34f02a45"
	rekorProofHash = "59a575f157274702c38de3ab1e1784226f391fb79500ebf9f02b4439fb77574c"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func (b *builder) rekor() {
	h := rfc6962.DefaultHasher
	root1, root2, cons := mustHex(rekorRoot1), mustHex(rekorRoot2), mustHex(rekorConsHash)
	good, err1 := base64.StdEncoding.DecodeString(rekorValidBody)
	bad, err2 := base64.StdEncoding.DecodeString(rekorBadBody)
	if err1 != nil || err2 != nil {
		b.fail("rekor bodies do not decode: %v %v", err1, err2)
		return
	}
	b.expect(rekorRootHash == rekorRoot2 && rekorProofHash == rekorRoot1, "rekor TestInclusion proof no longer matches TestConsistency roots")
	b.expect(len(good) == 567 && len(bad) == 567, "rekor body lengths %d %d", len(good), len(bad))

	// TestConsistency "valid consistency proof" (verify_test.go:93-106, wantErr false):
	// size 1 root1 -> size 2 root2 with proof [d3be...], which by RFC 9162 section 2.1.4
	// is [MTH(D[1:2])], the leaf hash of entry 1.
	b.expect(proof.VerifyConsistency(h, 1, 2, [][]byte{cons}, root1, root2) == nil, "transparency-dev/merkle rejects rekor TestConsistency 'valid consistency proof'")
	b.expect(bytes.Equal(h.HashChildren(root1, cons), root2), "rekor root2 is not HashChildren(root1, consistency hash)")
	goodLeaf := h.HashLeaf(good)
	b.expect(bytes.Equal(goodLeaf, cons), "rekor 'valid inclusion' body does not hash to the TestConsistency hash")
	b.expect(bytes.Equal(goodLeaf, refLeaf(good)), "rekor leaf hash disagrees with the RFC reference")
	badLeaf := h.HashLeaf(bad)
	// root0 (line 70) is a placeholder used only as the old root of a size-0
	// checkpoint in 'invalid consistency - empty log'; it is not an MTH, so it is
	// not held as a tree.
	b.expect(!bytes.Equal(mustHex(rekorRoot0), h.EmptyRoot()), "rekor root0 unexpectedly equals the empty root")

	b.f.HashChecks = append(b.f.HashChecks,
		HashCheck{
			Name:     "rekor v1.5.4 pkg/verify/verify_test.go:200 TestInclusion 'valid inclusion' entry body (567 bytes, base64-decoded); hash = verify_test.go:71 TestConsistency hashes[0], the size 1 to 2 consistency proof, which is the leaf hash of entry 1",
			Kind:     "leaf",
			InputHex: sp(hx(good)),
			Hash:     rekorConsHash,
		},
		HashCheck{
			Name:     "rekor v1.5.4 pkg/verify/verify_test.go:221 TestInclusion 'invalid inclusion - bad body hash' entry body (first base64 character e changed to a); hash computed with rfc6962 HashLeaf",
			Kind:     "leaf",
			InputHex: sp(hx(bad)),
			Hash:     hx(badLeaf),
		},
		HashCheck{
			Name:  "rekor v1.5.4 pkg/verify/verify_test.go:67-71,93-106 TestConsistency 'valid consistency proof': root2 = node(root1, hashes[0])",
			Kind:  "node",
			Left:  sp(rekorRoot1),
			Right: sp(rekorConsHash),
			Hash:  rekorRoot2,
		},
	)
	b.f.Trees = append(b.f.Trees,
		Tree{
			Name:       "rekor v1.5.4 pkg/verify/verify_test.go:69,97 TestConsistency root1: the size 1 root (leaf data not published)",
			LeafHashes: []string{rekorRoot1},
			TreeSize:   1,
			Root:       rekorRoot1,
		},
		Tree{
			Name:       "rekor v1.5.4 pkg/verify/verify_test.go:67-71,93-106 TestConsistency root2: the size 2 root; leaf 0 hash = root1, leaf 1 hash = hashes[0] (entry 1 is the TestInclusion body; entry 0 data not published)",
			LeafHashes: []string{rekorRoot1, rekorConsHash},
			TreeSize:   2,
			Root:       rekorRoot2,
		},
	)
	b.addPublished(Inclusion{
		Name:                "rekor v1.5.4 pkg/verify/verify_test.go:197-217 TestInclusion 'valid inclusion' (wantErr false): entry 1 of 2, leaf = HashLeaf(body)",
		LeafHash:            hx(goodLeaf),
		LeafIndex:           rekorLogIndex,
		TreeSize:            rekorTreeSize,
		Path:                []string{rekorProofHash},
		Root:                rekorRootHash,
		UpstreamExpectation: "valid",
	}, nil)
	b.addPublished(Inclusion{
		Name:                "rekor v1.5.4 pkg/verify/verify_test.go:218-238 TestInclusion 'invalid inclusion - bad body hash' (wantErr true): the valid proof with a corrupted body",
		LeafHash:            hx(badLeaf),
		LeafIndex:           rekorLogIndex,
		TreeSize:            rekorTreeSize,
		Path:                []string{rekorProofHash},
		Root:                rekorRootHash,
		UpstreamExpectation: "invalid",
	}, nil)
}
