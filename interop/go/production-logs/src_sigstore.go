// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// verifyRekorCheckpoint is adapted from github.com/sigstore/rekor@v1.5.4
// pkg/util/signed_note.go:74-115 and :150-200 (Apache-2.0). License text:
// LICENSE-rekor; see NOTICE.

package main

// Rekor inclusion proofs carried in sigstore-go v1.3.0 test bundles (Apache-2.0).
// sigstore-go pkg/verify/tlog.go:112-123 sends every bundle entry that has an
// inclusion proof to pkg/tlog/entry.go:466-501 VerifyInclusion, which calls
// rekor pkg/verify VerifyInclusion (transparency-dev/merkle proof.VerifyInclusion
// over rfc6962 HashLeaf(canonicalizedBody)) and then VerifyCheckpointSignature.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/transparency-dev/merkle/rfc6962"
)

type sigstoreBundle struct {
	VerificationMaterial struct {
		TlogEntries []struct {
			LogIndex string `json:"logIndex"`
			LogID    struct {
				KeyID string `json:"keyId"`
			} `json:"logId"`
			KindVersion struct {
				Kind    string `json:"kind"`
				Version string `json:"version"`
			} `json:"kindVersion"`
			InclusionProof *struct {
				LogIndex   string   `json:"logIndex"`
				RootHash   string   `json:"rootHash"`
				TreeSize   string   `json:"treeSize"`
				Hashes     []string `json:"hashes"`
				Checkpoint struct {
					Envelope string `json:"envelope"`
				} `json:"checkpoint"`
			} `json:"inclusionProof"`
			CanonicalizedBody string `json:"canonicalizedBody"`
		} `json:"tlogEntries"`
	} `json:"verificationMaterial"`
}

type trustedRoot struct {
	Tlogs []struct {
		BaseURL   string `json:"baseUrl"`
		PublicKey struct {
			RawBytes string `json:"rawBytes"`
		} `json:"publicKey"`
		LogID struct {
			KeyID string `json:"keyId"`
		} `json:"logId"`
	} `json:"tlogs"`
}

type sigstoreSource struct {
	bundle, trustedRoot string
	bundleLines         string // tlogEntries[0] line range in the bundle
	rootLines           string // tlogs[0] line range in the trusted root
	test                string // upstream test that asserts the bundle verifies
}

var sigstoreSources = []sigstoreSource{
	{
		bundle:      "sigstore.js@2.0.0-provenance.sigstore.json",
		trustedRoot: "public-good.json",
		bundleLines: "12-46",
		rootLines:   "4-17",
		test:        "pkg/verify/signed_entity_test.go:106-131 TestEntitySignedByPublicGoodWithTlogVerifiesSuccessfully",
	},
	{
		bundle:      "othername.sigstore.json",
		trustedRoot: "scaffolding.json",
		bundleLines: "8-34",
		rootLines:   "4-17",
		test:        "pkg/verify/signed_entity_test.go:230-254 TestEntityWithOthernameSan",
	},
}

// verifyRekorCheckpoint checks a Rekor v1 signed checkpoint with the Go standard
// library, adapted from rekor v1.5.4 pkg/util/signed_note.go:150-200 (parse: text up
// to the last blank line; signature lines "<em dash U+2014> name base64(4-byte key
// hint || ASN.1 ECDSA signature)") and :74-115 (verify: the hint is the first 4
// bytes of SHA-256 of the PKIX public key, the ECDSA signature is over
// SHA-256(text)). It returns the origin line, tree size and root hash.
// emDash is U+2014, which begins every signature line of a signed note.
var emDash = string(rune(0x2014))

func verifyRekorCheckpoint(env string, der []byte) (origin string, size uint64, root []byte, err error) {
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", 0, nil, err
	}
	pub, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return "", 0, nil, fmt.Errorf("log key is %T, not ECDSA", pk)
	}
	keyHash := sha256.Sum256(der)
	data := []byte(env)
	split := bytes.LastIndex(data, []byte("\n\n"))
	if split < 0 {
		return "", 0, nil, fmt.Errorf("malformed note")
	}
	text, sigs := data[:split+1], data[split+2:]
	digest := sha256.Sum256(text)
	nsig := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(sigs), "\n"), "\n") {
		f := strings.Fields(strings.TrimPrefix(line, emDash+" "))
		if !strings.HasPrefix(line, emDash+" ") || len(f) != 2 {
			return "", 0, nil, fmt.Errorf("malformed signature line %q", line)
		}
		sb, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(sb) < 5 {
			return "", 0, nil, fmt.Errorf("malformed signature")
		}
		if binary.BigEndian.Uint32(sb[:4]) != binary.BigEndian.Uint32(keyHash[:4]) {
			return "", 0, nil, fmt.Errorf("signature key hint does not match the log key")
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sb[4:]) {
			return "", 0, nil, fmt.Errorf("checkpoint signature does not verify")
		}
		nsig++
	}
	if nsig == 0 {
		return "", 0, nil, fmt.Errorf("no signatures")
	}
	lines := strings.Split(string(text), "\n")
	if len(lines) < 4 {
		return "", 0, nil, fmt.Errorf("short checkpoint")
	}
	size, err = strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return "", 0, nil, err
	}
	root, err = base64.StdEncoding.DecodeString(lines[2])
	return lines[0], size, root, err
}

func (b *builder) sigstore() {
	for _, src := range sigstoreSources {
		var bu sigstoreBundle
		if err := json.Unmarshal(readVendored("sigstore-go/pkg/testing/data/bundles/"+src.bundle), &bu); err != nil {
			b.fail("sigstore-go %s: %v", src.bundle, err)
			continue
		}
		var tr trustedRoot
		if err := json.Unmarshal(readVendored("sigstore-go/pkg/testing/data/trusted-roots/"+src.trustedRoot), &tr); err != nil {
			b.fail("sigstore-go %s: %v", src.trustedRoot, err)
			continue
		}
		b.expect(len(bu.VerificationMaterial.TlogEntries) == 1, "sigstore-go %s has %d tlog entries", src.bundle, len(bu.VerificationMaterial.TlogEntries))
		b.expect(len(tr.Tlogs) == 1, "sigstore-go %s has %d tlogs", src.trustedRoot, len(tr.Tlogs))
		if len(bu.VerificationMaterial.TlogEntries) == 0 || len(tr.Tlogs) == 0 {
			continue
		}
		e := bu.VerificationMaterial.TlogEntries[0]
		tl := tr.Tlogs[0]
		ip := e.InclusionProof
		if ip == nil {
			b.fail("sigstore-go %s has no inclusion proof", src.bundle)
			continue
		}
		der, err := base64.StdEncoding.DecodeString(tl.PublicKey.RawBytes)
		if err != nil {
			b.fail("sigstore-go %s key: %v", src.trustedRoot, err)
			continue
		}
		keyID := sha256.Sum256(der)
		b.expect(base64.StdEncoding.EncodeToString(keyID[:]) == tl.LogID.KeyID, "sigstore-go %s logId is not SHA-256 of the key", src.trustedRoot)
		b.expect(e.LogID.KeyID == tl.LogID.KeyID, "sigstore-go %s entry logId %s is not the trusted log %s", src.bundle, e.LogID.KeyID, tl.LogID.KeyID)

		body, err1 := base64.StdEncoding.DecodeString(e.CanonicalizedBody)
		root, err2 := base64.StdEncoding.DecodeString(ip.RootHash)
		idx, err3 := strconv.ParseUint(ip.LogIndex, 10, 64)
		size, err4 := strconv.ParseUint(ip.TreeSize, 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			b.fail("sigstore-go %s: bad fields %v %v %v %v", src.bundle, err1, err2, err3, err4)
			continue
		}
		var path [][]byte
		for _, hs := range ip.Hashes {
			p, err := base64.StdEncoding.DecodeString(hs)
			if err != nil {
				b.fail("sigstore-go %s: hash %q: %v", src.bundle, hs, err)
			}
			path = append(path, p)
		}
		origin, cpSize, cpRoot, err := verifyRekorCheckpoint(ip.Checkpoint.Envelope, der)
		if err != nil {
			b.fail("sigstore-go %s checkpoint: %v", src.bundle, err)
			continue
		}
		b.expect(cpSize == size && bytes.Equal(cpRoot, root), "sigstore-go %s: signed checkpoint (%d, %s) is not the proof's (%d, %s)", src.bundle, cpSize, hx(cpRoot), size, hx(root))
		leaf := rfc6962.DefaultHasher.HashLeaf(body)
		b.expect(bytes.Equal(leaf, refLeaf(body)), "sigstore-go %s leaf hash disagrees with the RFC reference", src.bundle)

		b.f.HashChecks = append(b.f.HashChecks, HashCheck{
			Name:     fmt.Sprintf("sigstore-go v1.3.0 pkg/testing/data/bundles/%s tlogEntries[0].canonicalizedBody (%s %s Rekor entry, %d bytes, base64-decoded); hash computed with rfc6962 HashLeaf", src.bundle, e.KindVersion.Kind, e.KindVersion.Version, len(body)),
			Kind:     "leaf",
			InputHex: sp(hx(body)),
			Hash:     hx(leaf),
		})
		b.addPublished(Inclusion{
			Name: fmt.Sprintf("sigstore-go v1.3.0 pkg/testing/data/bundles/%s:%s tlogEntries[0].inclusionProof: Rekor log %q (%s), entry logIndex %s, proof index %d of tree size %d, %d hashes, root = the signed checkpoint's (ECDSA signature verified with trusted-roots/%s:%s); upstream %s",
				src.bundle, src.bundleLines, origin, tl.BaseURL, e.LogIndex, idx, size, len(path), src.trustedRoot, src.rootLines, src.test),
			LeafHash:            hx(leaf),
			LeafIndex:           idx,
			TreeSize:            size,
			Path:                hxs(path),
			Root:                hx(root),
			UpstreamExpectation: "valid",
		}, nil)
	}
}
