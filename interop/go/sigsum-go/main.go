// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0 AND BSD-2-Clause
//
// The fixture entry names built here quote short expressions and line
// references from sigsum.org/sigsum-go@v0.14.1 (pkg/merkle/tree_test.go,
// pkg/proof/proof_test.go, tests/sigsum-submit-test, doc/tools.md),
// BSD-2-Clause, Copyright (c) 2021, The Sigsum Project Authors. The license
// text is LICENSE-sigsum-go in this directory; NOTICE lists it.

// This program builds and checks the sigsum-go interop fixture file, and
// checks the truestamp_merkle library's own known answers with sigsum-go. In
// the truestamp_merkle repository it is interop/go/sigsum-go/, the fixture
// file is vectors/interop/sigsum-go.json and the library's known answers are
// vectors/merkle.json. From the program directory:
//
//	go run . -fixtures ../../../vectors/interop/sigsum-go.json            check the fixture file
//	go run . -fixtures ../../../vectors/interop/sigsum-go.json -write     regenerate it, then check it
//	go run . -fixtures <path> -ours ../../../vectors/merkle.json          also check the library's known answers
//
// -fixtures is required. It prints "OK fixtures sigsum.org/sigsum-go@v0.14.1:
// <counts>" and, with -ours, "OK ours sigsum.org/sigsum-go@v0.14.1: <counts>",
// or one "FAIL fixtures ", "FAIL ours " or "FAIL usage: " line per problem,
// and exits 1 on any failure. The program reads nothing but the -fixtures
// and -ours files: every upstream literal it uses is copied into upstream.go
// (BSD-2-Clause, see LICENSE-sigsum-go and NOTICE), and
// every value is computed or checked with sigsum.org/sigsum-go v0.14.1's own
// functions (merkle.HashLeafNode, merkle.HashInteriorNode,
// merkle.HashEmptyTree, merkle.Tree, merkle.VerifyInclusion,
// merkle.VerifyInclusionTail, merkle.VerifyConsistency, types.Leaf,
// proof.SigsumProof, requests.Leaf, policy.ParseConfig). reference.go is an
// independent RFC 9162 reference used only to confirm that sigsum's
// verdicts, roots and paths are the RFC 9162 ones.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
	"sigsum.org/sigsum-go/pkg/policy"
	"sigsum.org/sigsum-go/pkg/proof"
	"sigsum.org/sigsum-go/pkg/requests"
	"sigsum.org/sigsum-go/pkg/types"
)

const (
	implementation = "sigsum.org/sigsum-go"
	version        = "v0.14.1"
	license        = "BSD-2-Clause"
	ivPrefix       = "generated: pkg/merkle/tree_test.go TestInclusionValid seed 17 "
	dupPrefix      = "generated: duplicate-leaf tree "
)

// ---------------------------------------------------------------------------
// Fixture schema

type HashCheck struct {
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	InputHex *string `json:"input_hex,omitempty"`
	Left     *string `json:"left,omitempty"`
	Right    *string `json:"right,omitempty"`
	Hash     string  `json:"hash"`
}

type LeafDataRule struct {
	Encoding string `json:"encoding"`
	First    uint64 `json:"first"`
}

type Tree struct {
	Name         string        `json:"name"`
	LeafData     []string      `json:"leaf_data"`
	LeafHashes   []string      `json:"leaf_hashes"`
	LeafDataRule *LeafDataRule `json:"leaf_data_rule"`
	TreeSize     uint64        `json:"tree_size"`
	Root         string        `json:"root"`
}

type Inclusion struct {
	Name                string   `json:"name"`
	LeafHash            string   `json:"leaf_hash"`
	LeafIndex           uint64   `json:"leaf_index"`
	TreeSize            uint64   `json:"tree_size"`
	Path                []string `json:"path"`
	Root                string   `json:"root"`
	Valid               bool     `json:"valid"`
	RFC9162Valid        *bool    `json:"rfc9162_valid,omitempty"`
	UpstreamExpectation string   `json:"upstream_expectation"`
}

type Fixture struct {
	Implementation string      `json:"implementation"`
	Version        string      `json:"version"`
	License        string      `json:"license"`
	Sources        []string    `json:"sources"`
	EmptyRoot      *string     `json:"empty_root"`
	HashChecks     []HashCheck `json:"hash_checks"`
	Trees          []Tree      `json:"trees"`
	Inclusion      []Inclusion `json:"inclusion"`
	Deviations     []string    `json:"deviations"`
	Discrepancies  []string    `json:"discrepancies"`
	Notes          string      `json:"notes"`
}

// ---------------------------------------------------------------------------
// Small helpers

func hx(b []byte) string                { return hex.EncodeToString(b) }
func hh(h crypto.Hash) string           { return hex.EncodeToString(h[:]) }
func sp(s string) *string               { return &s }
func u64be(i uint64) []byte             { b := make([]byte, 8); binary.BigEndian.PutUint64(b, i); return b }
func node(l, r crypto.Hash) crypto.Hash { return merkle.HashInteriorNode(&l, &r) }

func hexPath(p []crypto.Hash) []string {
	out := make([]string, 0, len(p))
	for _, h := range p {
		out = append(out, hh(h))
	}
	return out
}

func toH32s(p []crypto.Hash) []h32 {
	out := make([]h32, len(p))
	for i, h := range p {
		out[i] = h32(h)
	}
	return out
}

// verify is the implementation's verdict: merkle.VerifyInclusion returns nil.
func verify(leaf crypto.Hash, index, size uint64, root crypto.Hash, path []crypto.Hash) bool {
	return merkle.VerifyInclusion(&leaf, index, size, &root, slices.Clone(path)) == nil
}

// split is the largest power of two smaller than n (n >= 2).
func split(n int) int { return refSplit(n) }

// sigsumMTH is the RFC 9162 section 2.1.1 recursion with sigsum's own hash
// functions. merkle.Tree cannot hold a tree with duplicate leaves (its
// AddLeafHash refuses a leaf hash it already has), so such trees are built
// with this and sigsumPath, and checked with merkle.VerifyInclusion and
// merkle.VerifyInclusionTail. The shape code is ours; every hash is sigsum's.
func sigsumMTH(leaves []crypto.Hash) crypto.Hash {
	switch len(leaves) {
	case 0:
		return merkle.HashEmptyTree()
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return node(sigsumMTH(leaves[:k]), sigsumMTH(leaves[k:]))
}

// sigsumPath is RFC 9162 section 2.1.3.1 PATH(m, D[n]), bottom to top, with
// sigsum's own hash functions.
func sigsumPath(m int, leaves []crypto.Hash) []crypto.Hash {
	if len(leaves) <= 1 {
		return []crypto.Hash{}
	}
	k := split(len(leaves))
	if m < k {
		return append(sigsumPath(m, leaves[:k]), sigsumMTH(leaves[k:]))
	}
	return append(sigsumPath(m-k, leaves[k:]), sigsumMTH(leaves[:k]))
}

// firstDuplicate is the index of the first leaf hash that already occurs
// earlier in leaves, or -1.
func firstDuplicate(leaves []crypto.Hash) int {
	seen := map[crypto.Hash]bool{}
	for i, l := range leaves {
		if seen[l] {
			return i
		}
		seen[l] = true
	}
	return -1
}

// ---------------------------------------------------------------------------
// The four real Sigsum proofs in pkg/proof/proof_test.go

type realProof struct {
	label    string // how the fixture names it
	where    string // proof_test.go lines of the proof text
	msgFrom  string // where the message comes from
	msg      crypto.Hash
	sp       proof.SigsumProof
	leaf     types.Leaf
	leafHash crypto.Hash
	upstream string // upstream_expectation for the proof itself
}

func parseProof(ascii string) (proof.SigsumProof, error) {
	var p proof.SigsumProof
	err := p.FromASCII(bytes.NewBufferString(ascii))
	return p, err
}

func realProofs() ([]realProof, error) {
	type in struct {
		label, where, msgFrom, ascii, upstream string
		msg                                    crypto.Hash
	}
	nc, ncMsg, _, _ := testVerifyNoCosignaturesInputs()
	v, vMsg, _, _, _ := testVerifyInputs()
	ins := []in{
		{`TestASCII "size 1"`, "pkg/proof/proof_test.go:19-26",
			`message printf "%31s\n" "foo-1" (tests/sigsum-submit-test:31-37, x=1; the version 1 proof at proof_test.go:79 carries its checksum prefix 5cc0)`,
			testASCIITable[0].ascii, "none", submitTestMessage(1)},
		{`TestASCII "size 4"`, "pkg/proof/proof_test.go:27-38",
			`message printf "%31s\n" "foo-4" (tests/sigsum-submit-test:31-37, x=4; the version 1 proof at proof_test.go:101 carries its checksum prefix 7e28)`,
			testASCIITable[1].ascii, "none", submitTestMessage(4)},
		{"TestVerifyNoCosignatures", "pkg/proof/proof_test.go:134-145",
			`message "foo-4" padded to 32 bytes (proof_test.go:146-149)`, nc, "valid", ncMsg},
		{"TestVerify", "pkg/proof/proof_test.go:165-177",
			`message "foo-4" padded to 32 bytes (proof_test.go:178-181)`, v, "valid", vMsg},
	}
	var out []realProof
	for _, x := range ins {
		p, err := parseProof(x.ascii)
		if err != nil {
			return nil, fmt.Errorf("%s: FromASCII: %v", x.label, err)
		}
		checksum := crypto.HashBytes(x.msg[:])
		leaf := p.Leaf.ToLeaf(&checksum)
		out = append(out, realProof{
			label: x.label, where: x.where, msgFrom: x.msgFrom, msg: x.msg, sp: p,
			leaf: leaf, leafHash: leaf.ToHash(), upstream: x.upstream,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The two poc.sigsum.org example proofs in doc/tools.md

// docExamples holds what doc/tools.md:419-471 gives: the submitter key, the
// log key from the policy, the add-leaf request of the second example, and
// the two proofs with their rebuilt leaves.
type docExamples struct {
	submitKey crypto.PublicKey
	logKey    crypto.PublicKey
	request   requests.Leaf
	proofs    []realProof // size 3 (lines 430-441), then size 4 (lines 446-466)
}

// docLines returns the upstream lines held by a "verbatim text" raw string.
func docLines(s string) []string {
	return strings.Split(strings.TrimSuffix(strings.TrimPrefix(s, "\n"), "\n"), "\n")
}

// echoInput returns what `$ echo "<text>" | ...` writes: the text and a newline.
func echoInput(cmd string) (string, error) {
	rest, ok := strings.CutPrefix(cmd, `$ echo "`)
	if !ok {
		return "", fmt.Errorf("%q is not an echo command", cmd)
	}
	text, _, ok := strings.Cut(rest, `"`)
	if !ok {
		return "", fmt.Errorf("%q has no closing quote", cmd)
	}
	return text + "\n", nil
}

// parseDocExamples parses the doc/tools.md examples with sigsum's own parsers
// and rebuilds each proof's leaf as checksum || signature || key hash, where
// checksum = SHA-256(message) and message = SHA-256(echo output). It returns
// an error if any fact the reconstruction rests on does not hold: the key
// hashes, the log key hash, the request's message, key and signature, and the
// chain between the two proofs (the size 4 proof's node_hash 1 is the rebuilt
// size 3 leaf hash, its node_hash 2 is the size 3 proof's node_hash 1).
func parseDocExamples() (docExamples, error) {
	var d docExamples
	var err error
	key := docLines(docToolsSubmitKey)
	if len(key) != 2 {
		return d, fmt.Errorf("doc/tools.md:268-269: %d lines", len(key))
	}
	if d.submitKey, err = crypto.PublicKeyFromHex(key[1]); err != nil {
		return d, fmt.Errorf("doc/tools.md:269: %v", err)
	}
	pol, err := policy.ParseConfig(strings.NewReader(strings.TrimPrefix(docToolsPolicy, "\n")))
	if err != nil {
		return d, fmt.Errorf("doc/tools.md:424-425: policy.ParseConfig: %v", err)
	}
	logs := pol.GetLogs()
	if len(logs) != 1 {
		return d, fmt.Errorf("doc/tools.md:424-425: %d logs, want 1", len(logs))
	}
	d.logKey = logs[0].PublicKey

	// Size 3: the command on line 430, then the proof.
	l3 := docLines(docToolsSize3)
	in3, err := echoInput(l3[0])
	if err != nil {
		return d, fmt.Errorf("doc/tools.md:430: %v", err)
	}
	msg3 := crypto.HashBytes([]byte(in3))

	// The request: the command on line 446, then message, signature, public_key.
	lr := docLines(docToolsRequest)
	in4, err := echoInput(lr[0])
	if err != nil {
		return d, fmt.Errorf("doc/tools.md:446: %v", err)
	}
	if err := d.request.FromASCII(strings.NewReader(strings.Join(lr[1:], "\n") + "\n")); err != nil {
		return d, fmt.Errorf("doc/tools.md:447-449: requests.Leaf.FromASCII: %v", err)
	}
	if d.request.Message != crypto.HashBytes([]byte(in4)) {
		return d, fmt.Errorf("doc/tools.md:447: message is not SHA-256 of the echo output on line 446")
	}
	if d.request.PublicKey != d.submitKey {
		return d, fmt.Errorf("doc/tools.md:449: public_key is not the key on line 269")
	}

	l4 := docLines(docToolsSize4)
	ins := []struct {
		label, where, msgFrom string
		lines                 []string
		msg                   crypto.Hash
	}{
		{"poc.sigsum.org example (size 3)", "doc/tools.md:430-441",
			`message SHA-256("Hello old friend" and a newline), the echo output on line 430, hashed by default as lines 343-344 say`,
			l3[1:], msg3},
		{"poc.sigsum.org example (size 4)", "doc/tools.md:446-466",
			`message from the request, line 447, which is SHA-256("Hello again" and a newline), the echo output on line 446`,
			l4[1:], d.request.Message},
	}
	keyHash := crypto.HashBytes(d.submitKey[:])
	logKeyHash := crypto.HashBytes(d.logKey[:])
	for _, x := range ins {
		p, err := parseProof(strings.Join(x.lines, "\n") + "\n")
		if err != nil {
			return d, fmt.Errorf("%s: FromASCII: %v", x.where, err)
		}
		if p.Leaf.KeyHash != keyHash {
			return d, fmt.Errorf("%s: the leaf's key hash is not SHA-256 of the key on line 269", x.where)
		}
		if p.LogKeyHash != logKeyHash {
			return d, fmt.Errorf("%s: log is not SHA-256 of the policy's log key (line 424)", x.where)
		}
		checksum := crypto.HashBytes(x.msg[:])
		leaf := p.Leaf.ToLeaf(&checksum)
		d.proofs = append(d.proofs, realProof{
			label: x.label, where: x.where, msgFrom: x.msgFrom, msg: x.msg, sp: p,
			leaf: leaf, leafHash: leaf.ToHash(), upstream: "none",
		})
	}
	p3, p4 := d.proofs[0].sp, d.proofs[1].sp
	if p3.TreeHead.Size != 3 || p3.Inclusion.LeafIndex != 2 || len(p3.Inclusion.Path) != 1 {
		return d, fmt.Errorf("doc/tools.md:430-441: expected size 3, leaf_index 2, one node_hash")
	}
	if p4.TreeHead.Size != 4 || p4.Inclusion.LeafIndex != 3 || len(p4.Inclusion.Path) != 2 {
		return d, fmt.Errorf("doc/tools.md:454-466: expected size 4, leaf_index 3, two node_hash")
	}
	if p4.Leaf.Signature != d.request.Signature {
		return d, fmt.Errorf("doc/tools.md:457: the leaf signature is not the request's (line 448)")
	}
	if p4.Inclusion.Path[0] != d.proofs[0].leafHash {
		return d, fmt.Errorf("doc/tools.md:464: node_hash 1 is not the rebuilt size 3 leaf hash %s", hh(d.proofs[0].leafHash))
	}
	if p4.Inclusion.Path[1] != p3.Inclusion.Path[0] {
		return d, fmt.Errorf("doc/tools.md:465: node_hash 2 is not the size 3 proof's node_hash (line 440)")
	}
	return d, nil
}

// ---------------------------------------------------------------------------
// The generated duplicate-leaf tree

// dupTreeData is its leaf data, newLeaves values (8-byte big-endian,
// tree_test.go:362-370) with repeats: leaves 0..1 and 2..3 are the same pair,
// so the size 4 subtree is HashInteriorNode(h01, h01); leaves 4 and 5 are
// identical siblings; leaf 6, alone on the right edge, repeats leaf 0.
var dupTreeData = []uint64{0, 1, 0, 1, 2, 2, 0}

func dupTreeLeaves() []crypto.Hash {
	var out []crypto.Hash
	for _, d := range dupTreeData {
		out = append(out, merkle.HashLeafNode(u64be(d)))
	}
	return out
}

// ---------------------------------------------------------------------------
// TestInclusionValid, materialized

type ivCase struct {
	i, n              int
	bitToFlip, target int // -1, -1 for the unmodified proof; target is upstream's hashToFlip
	leaf, root        crypto.Hash
	proof             []crypto.Hash
}

// materializeInclusionValid runs the adapted upstream test and returns every
// recorded case in upstream order (for each (i, n): the proof, then its
// corruption), plus any assertion upstream would have reported.
func materializeInclusionValid() ([]ivCase, []string) {
	var errs []string
	var cases []ivCase
	testInclusionValid(fatalT{errs: &errs}, func(i, n int, leaf crypto.Hash, p []crypto.Hash, root crypto.Hash, bitToFlip, hashToFlip int) {
		cases = append(cases, ivCase{i: i, n: n, bitToFlip: bitToFlip, target: hashToFlip, leaf: leaf, root: root, proof: p})
	})
	return cases, errs
}

// selectPairs picks the deterministic subset of TestInclusionValid (i, n)
// pairs that goes into the file; see the notes for the rule.
// It also returns how many pairs the coverage step added and how many
// (path length, flip target) classes the full run has.
func selectPairs(cases []ivCase) (map[[2]int]bool, int, int) {
	sel := map[[2]int]bool{}
	for _, c := range cases {
		if c.bitToFlip >= 0 {
			continue
		}
		i, n := c.i, c.n
		keep := n <= 32
		if n > 32 {
			k := split(n)
			keep = i == 0 || i == k-1 || i == k || i == n-1
		}
		if keep {
			sel[[2]int{i, n}] = true
		}
	}
	// Every corruption class (path length, flipped element) that the full
	// run produces is kept at least once: its first pair in upstream order.
	type class struct{ pathLen, target int }
	covered := map[class]bool{}
	for _, c := range cases {
		if c.bitToFlip >= 0 && sel[[2]int{c.i, c.n}] {
			covered[class{len(c.proof), c.target}] = true
		}
	}
	all := map[class]bool{}
	added := 0
	for _, c := range cases {
		if c.bitToFlip < 0 {
			continue
		}
		k := class{len(c.proof), c.target}
		all[k] = true
		if !covered[k] {
			covered[k] = true
			sel[[2]int{c.i, c.n}] = true
			added++
		}
	}
	return sel, added, len(all)
}

func flipDesc(c ivCase) string {
	if c.target == 0 {
		return fmt.Sprintf("bitToFlip=%d hashToFlip=0 (flips bit %d of the leaf hash)", c.bitToFlip, c.bitToFlip)
	}
	return fmt.Sprintf("bitToFlip=%d hashToFlip=%d (flips bit %d of path[%d])", c.bitToFlip, c.target, c.bitToFlip, c.target-1)
}

// ---------------------------------------------------------------------------
// build: the whole fixture from the upstream literals and the implementation

func build() (*Fixture, error) {
	f := &Fixture{
		Implementation: implementation,
		Version:        version,
		License:        license,
		Sources:        sources,
		Deviations:     deviations,
		Discrepancies:  []string{},
	}

	// Empty root: the tree_test.go:70 literal.
	wants := testGetRootHashWants()
	if wants[0] != merkle.HashEmptyTree() {
		return nil, fmt.Errorf("tree_test.go:70 literal is not merkle.HashEmptyTree()")
	}
	f.EmptyRoot = sp(hh(wants[0]))

	rps, err := realProofs()
	if err != nil {
		return nil, err
	}
	doc, err := parseDocExamples()
	if err != nil {
		return nil, err
	}

	// Hash checks: the real proofs.
	for _, rp := range rps {
		f.HashChecks = append(f.HashChecks, HashCheck{
			Name: fmt.Sprintf("published: %s %s leaf, 128 bytes = SHA-256(message) || signature || key hash (pkg/types/leaf.go:51-61); %s; signature and key hash from the proof's leaf line",
				rp.where, rp.label, rp.msgFrom),
			Kind: "leaf", InputHex: sp(hx(rp.leaf.ToBinary())), Hash: hh(rp.leafHash),
		})
		if rp.sp.TreeHead.Size == 1 {
			continue
		}
		p := rp.sp.Inclusion.Path
		if rp.sp.Inclusion.LeafIndex != 3 || rp.sp.TreeHead.Size != 4 || len(p) != 2 {
			return nil, fmt.Errorf("%s: expected leaf_index 3, size 4, two node hashes", rp.label)
		}
		n23 := node(p[0], rp.leafHash)
		f.HashChecks = append(f.HashChecks,
			HashCheck{
				Name: fmt.Sprintf("published: %s %s, first step of the inclusion proof: HashInteriorNode(node_hash 1, leaf hash) = the subtree over leaves 2..3", rp.where, rp.label),
				Kind: "node", Left: sp(hh(p[0])), Right: sp(hh(rp.leafHash)), Hash: hh(n23),
			},
			HashCheck{
				Name: fmt.Sprintf("published: %s %s, second step: HashInteriorNode(node_hash 2, subtree 2..3) = the root_hash literal", rp.where, rp.label),
				Kind: "node", Left: sp(hh(p[1])), Right: sp(hh(n23)), Hash: hh(node(p[1], n23)),
			})
	}

	// Hash checks: the doc/tools.md proofs.
	d3, d4 := doc.proofs[0], doc.proofs[1]
	f.HashChecks = append(f.HashChecks,
		HashCheck{
			Name: fmt.Sprintf("published: %s %s leaf, 128 bytes = SHA-256(message) || signature || key hash (pkg/types/leaf.go:51-61); %s; signature and key hash from the leaf line (433); the size 4 proof's node_hash 1 (line 464) is this leaf hash",
				d3.where, d3.label, d3.msgFrom),
			Kind: "leaf", InputHex: sp(hx(d3.leaf.ToBinary())), Hash: hh(d3.leafHash),
		},
		HashCheck{
			Name: fmt.Sprintf("published: %s %s, the one step of the inclusion proof: HashInteriorNode(node_hash 1, leaf hash) = the root_hash literal (line 436)", d3.where, d3.label),
			Kind: "node", Left: sp(hh(d3.sp.Inclusion.Path[0])), Right: sp(hh(d3.leafHash)), Hash: hh(node(d3.sp.Inclusion.Path[0], d3.leafHash)),
		},
		HashCheck{
			Name: fmt.Sprintf("published: %s %s leaf, 128 bytes = SHA-256(message) || signature || key hash (pkg/types/leaf.go:51-61); %s; signature and key hash from the leaf line (457), the signature also on the request line 448",
				d4.where, d4.label, d4.msgFrom),
			Kind: "leaf", InputHex: sp(hx(d4.leaf.ToBinary())), Hash: hh(d4.leafHash),
		})
	{
		p := d4.sp.Inclusion.Path
		n23 := node(p[0], d4.leafHash)
		f.HashChecks = append(f.HashChecks,
			HashCheck{
				Name: fmt.Sprintf("published: %s %s, first step of the inclusion proof: HashInteriorNode(node_hash 1, leaf hash) = the subtree over leaves 2..3", d4.where, d4.label),
				Kind: "node", Left: sp(hh(p[0])), Right: sp(hh(d4.leafHash)), Hash: hh(n23),
			},
			HashCheck{
				Name: fmt.Sprintf("published: %s %s, second step: HashInteriorNode(node_hash 2, subtree 2..3) = the root_hash literal (line 460)", d4.where, d4.label),
				Kind: "node", Left: sp(hh(p[1])), Right: sp(hh(n23)), Hash: hh(node(p[1], n23)),
			})
	}

	// Hash checks: the newLeaves formula values.
	hashes7, h01, h23, h0123, h45, h456 := testConsistencyNodes()
	for i := 0; i < 7; i++ {
		where := "tree_test.go:63 newLeaves(5), used by TestGetRootHash and TestInclusion"
		if i >= 5 {
			where = "tree_test.go:257 newLeaves(7), used by TestConsistency"
		}
		f.HashChecks = append(f.HashChecks, HashCheck{
			Name:     fmt.Sprintf("published: pkg/merkle/%s: leaf %d = HashLeafNode(8-byte big-endian %d) (newLeaves, tree_test.go:362-370)", where, i, i),
			Kind:     "leaf",
			InputHex: sp(hx(u64be(uint64(i)))),
			Hash:     hh(hashes7[i]),
		})
	}
	h := hashes7
	nodeChecks := []struct {
		name        string
		left, right crypto.Hash
		want        crypto.Hash // the value upstream's own expression gives
	}{
		{"h01 = HashInteriorNode(&hashes[0], &hashes[1]) (tree_test.go:64, 91, 258); root of size 2 (line 72)", h[0], h[1], h01},
		{"h23 = HashInteriorNode(&hashes[2], &hashes[3]) (tree_test.go:65, 92, 259)", h[2], h[3], h23},
		{"h0123 = HashInteriorNode(&h01, &h23) (tree_test.go:66, 93, 260); root of size 4 (line 74)", h01, h23, h0123},
		{"HashInteriorNode(&h01, &hashes[2]) (tree_test.go:73); root of size 3", h01, h[2], wants[3]},
		{"HashInteriorNode(&h0123, &hashes[4]) (tree_test.go:75); root of size 5", h0123, h[4], wants[5]},
		{"h45 = HashInteriorNode(&hashes[4], &hashes[5]) (tree_test.go:261, TestConsistency)", h[4], h[5], h45},
		{"h456 = HashInteriorNode(&h45, &hashes[6]) (tree_test.go:262, TestConsistency)", h45, h[6], h456},
	}
	for _, nc := range nodeChecks {
		if node(nc.left, nc.right) != nc.want {
			return nil, fmt.Errorf("node check %q does not match upstream's expression", nc.name)
		}
		f.HashChecks = append(f.HashChecks, HashCheck{
			Name: "published: pkg/merkle/" + nc.name,
			Kind: "node", Left: sp(hh(nc.left)), Right: sp(hh(nc.right)), Hash: hh(nc.want),
		})
	}

	// Trees: TestGetRootHash sizes 0..5.
	for size := 0; size <= 5; size++ {
		data, lh := []string{}, []string{}
		for i := 0; i < size; i++ {
			data = append(data, hx(u64be(uint64(i))))
			lh = append(lh, hh(hashes7[i]))
		}
		what := []string{
			`the literal "e3b0c442...b855" (line 70)`, "hashes[0] (line 71)", "h01 (line 72)",
			"HashInteriorNode(&h01, &hashes[2]) (line 73)", "h0123 (line 74)", "HashInteriorNode(&h0123, &hashes[4]) (line 75)",
		}[size]
		f.Trees = append(f.Trees, Tree{
			Name:       fmt.Sprintf("published: pkg/merkle/tree_test.go:62-87 TestGetRootHash size %d over newLeaves(5): root %s", size, what),
			LeafData:   data,
			LeafHashes: lh,
			TreeSize:   uint64(size),
			Root:       hh(wants[size]),
		})
	}
	// Trees: the real size 1 proof is a whole tree.
	rp1 := rps[0]
	f.Trees = append(f.Trees, Tree{
		Name:       fmt.Sprintf("published: %s %s: a size 1 Sigsum log whose root_hash literal (line 24) is the leaf hash", rp1.where, rp1.label),
		LeafData:   []string{hx(rp1.leaf.ToBinary())},
		LeafHashes: []string{hh(rp1.leafHash)},
		TreeSize:   1,
		Root:       hh(rp1.sp.TreeHead.RootHash),
	})

	// Trees: TestInclusionValid rootHashes, sizes 1..100.
	cases, errs := materializeInclusionValid()
	if len(errs) > 0 {
		return nil, fmt.Errorf("TestInclusionValid assertions failed: %v", errs[0])
	}
	rootAt := map[int]crypto.Hash{}
	for _, c := range cases {
		if c.bitToFlip < 0 {
			rootAt[c.n] = c.root
		}
	}
	for n := 1; n <= 100; n++ {
		f.Trees = append(f.Trees, Tree{
			Name:         fmt.Sprintf("generated: pkg/merkle/tree_test.go:121-130 TestInclusionValid rootHashes[%d], the root of newLeaves(100)[:%d] (leaf i data = 8-byte big-endian i)", n-1, n),
			LeafData:     nil,
			LeafHashes:   nil,
			LeafDataRule: &LeafDataRule{Encoding: "u64be", First: 0},
			TreeSize:     uint64(n),
			Root:         hh(rootAt[n]),
		})
	}

	// Trees: the generated duplicate-leaf tree.
	dl := dupTreeLeaves()
	dupRoot := sigsumMTH(dl)
	{
		data, lh := []string{}, []string{}
		for i, v := range dupTreeData {
			data = append(data, hx(u64be(v)))
			lh = append(lh, hh(dl[i]))
		}
		f.Trees = append(f.Trees, Tree{
			Name:       dupPrefix + dupTreeDesc,
			LeafData:   data,
			LeafHashes: lh,
			TreeSize:   uint64(len(dl)),
			Root:       hh(dupRoot),
		})
	}

	// Inclusion: the real proofs, then the doc/tools.md proofs.
	for _, rp := range rps {
		f.Inclusion = append(f.Inclusion, Inclusion{
			Name: fmt.Sprintf("published: %s %s: size %d, leaf_index %d, %d node_hash; leaf hash from the reconstructed leaf (%s)",
				rp.where, rp.label, rp.sp.TreeHead.Size, rp.sp.Inclusion.LeafIndex, len(rp.sp.Inclusion.Path), rp.msgFrom),
			LeafHash:            hh(rp.leafHash),
			LeafIndex:           rp.sp.Inclusion.LeafIndex,
			TreeSize:            rp.sp.TreeHead.Size,
			Path:                hexPath(rp.sp.Inclusion.Path),
			Root:                hh(rp.sp.TreeHead.RootHash),
			Valid:               verify(rp.leafHash, rp.sp.Inclusion.LeafIndex, rp.sp.TreeHead.Size, rp.sp.TreeHead.RootHash, rp.sp.Inclusion.Path),
			UpstreamExpectation: rp.upstream,
		})
	}
	for _, rp := range doc.proofs {
		f.Inclusion = append(f.Inclusion, Inclusion{
			Name: fmt.Sprintf("published: %s %s: size %d, leaf_index %d, %d node_hash; leaf hash from the reconstructed leaf (%s). upstream_expectation none: the doc asserts nothing about the proof, and under v0.14.1 its leaf signature and tree head signature do not verify, while the Merkle proof does",
				rp.where, rp.label, rp.sp.TreeHead.Size, rp.sp.Inclusion.LeafIndex, len(rp.sp.Inclusion.Path), rp.msgFrom),
			LeafHash:            hh(rp.leafHash),
			LeafIndex:           rp.sp.Inclusion.LeafIndex,
			TreeSize:            rp.sp.TreeHead.Size,
			Path:                hexPath(rp.sp.Inclusion.Path),
			Root:                hh(rp.sp.TreeHead.RootHash),
			Valid:               verify(rp.leafHash, rp.sp.Inclusion.LeafIndex, rp.sp.TreeHead.Size, rp.sp.TreeHead.RootHash, rp.sp.Inclusion.Path),
			UpstreamExpectation: rp.upstream,
		})
	}
	// Inclusion: TestInclusion's size 5 paths.
	paths5 := testInclusionPaths()
	for i, p := range paths5 {
		f.Inclusion = append(f.Inclusion, Inclusion{
			Name:                fmt.Sprintf("published: pkg/merkle/tree_test.go:103-117 TestInclusion path for leaf %d of newLeaves(5) (line %d), root HashInteriorNode(&h0123, &hashes[4]) (line 75); TestInclusionValid asserts this proof verifies", i, 104+i),
			LeafHash:            hh(hashes7[i]),
			LeafIndex:           uint64(i),
			TreeSize:            5,
			Path:                hexPath(p),
			Root:                hh(wants[5]),
			Valid:               verify(hashes7[i], uint64(i), 5, wants[5], p),
			UpstreamExpectation: "valid",
		})
	}
	// Inclusion: structural probes on published values.
	f.Inclusion = append(f.Inclusion, probes(rps, hashes7, h01, h0123, wants)...)

	// Inclusion: every leaf of the duplicate-leaf tree.
	for i := range dl {
		p := sigsumPath(i, dl)
		f.Inclusion = append(f.Inclusion, Inclusion{
			Name:                fmt.Sprintf("%sleaf %d of %d (data %d): RFC 9162 PATH built with sigsum's hash functions, verified with merkle.VerifyInclusion", dupPrefix, i, len(dl), dupTreeData[i]),
			LeafHash:            hh(dl[i]),
			LeafIndex:           uint64(i),
			TreeSize:            uint64(len(dl)),
			Path:                hexPath(p),
			Root:                hh(dupRoot),
			Valid:               verify(dl[i], uint64(i), uint64(len(dl)), dupRoot, p),
			UpstreamExpectation: "none",
		})
	}

	// Inclusion: the TestInclusionValid subset.
	sel, added, classes := selectPairs(cases)
	f.Notes = fmt.Sprintf(notesFormat, len(sel), 2*len(sel), added, classes)
	for _, c := range cases {
		if !sel[[2]int{c.i, c.n}] {
			continue
		}
		name := fmt.Sprintf("%si=%d n=%d: ProveInclusion proof", ivPrefix, c.i, c.n)
		exp := "valid"
		if c.bitToFlip >= 0 {
			name = fmt.Sprintf("%si=%d n=%d: %s", ivPrefix, c.i, c.n, flipDesc(c))
			exp = "invalid"
		}
		f.Inclusion = append(f.Inclusion, Inclusion{
			Name:                name,
			LeafHash:            hh(c.leaf),
			LeafIndex:           uint64(c.i),
			TreeSize:            uint64(c.n),
			Path:                hexPath(c.proof),
			Root:                hh(c.root),
			Valid:               verify(c.leaf, uint64(c.i), uint64(c.n), c.root, c.proof),
			UpstreamExpectation: exp,
		})
	}
	return f, nil
}

// probes builds generated structural probes from published values. Upstream
// asserts nothing about them; each verdict is merkle.VerifyInclusion's.
func probes(rps []realProof, leaves []crypto.Hash, h01, h0123 crypto.Hash, wants []crypto.Hash) []Inclusion {
	var out []Inclusion
	add := func(name string, leaf crypto.Hash, index, size uint64, path []crypto.Hash, root crypto.Hash) {
		out = append(out, Inclusion{
			Name: "generated: probe " + name, LeafHash: hh(leaf), LeafIndex: index, TreeSize: size,
			Path: hexPath(path), Root: hh(root), Valid: verify(leaf, index, size, root, path),
			UpstreamExpectation: "none",
		})
	}
	rp1 := rps[0]
	l := rp1.leafHash
	add(fmt.Sprintf("on %s %s (size 1): over-long path [leaf hash] with the chain root HashInteriorNode(leaf, leaf)", rp1.where, rp1.label),
		l, 0, 1, []crypto.Hash{l}, node(l, l))
	add(fmt.Sprintf("on %s %s (size 1): leaf_index 1 = tree_size", rp1.where, rp1.label), l, 1, 1, []crypto.Hash{}, l)
	add(fmt.Sprintf("on %s %s (size 1): tree_size 2 with the empty path and the size 1 root", rp1.where, rp1.label), l, 0, 2, []crypto.Hash{}, l)
	for _, rp := range rps[1:] {
		L, R, p := rp.leafHash, rp.sp.TreeHead.RootHash, rp.sp.Inclusion.Path
		on := fmt.Sprintf("on %s %s (leaf_index 3, size 4)", rp.where, rp.label)
		add(on+": right-edge truncation, path [node_hash 1] with the chain root HashInteriorNode(node_hash 1, leaf hash)",
			L, 3, 4, []crypto.Hash{p[0]}, node(p[0], L))
		add(on+": over-long path [node_hash 1, node_hash 2, node_hash 1] with the chain root HashInteriorNode(node_hash 1, root_hash)",
			L, 3, 4, []crypto.Hash{p[0], p[1], p[0]}, node(p[0], R))
		add(on+": leaf_index 4 = tree_size", L, 4, 4, p, R)
		add(on+": leaf_index 2 (the sibling position)", L, 2, 4, p, R)
		add(on+": tree_size 5", L, 3, 5, p, R)
		add(on+": path order reversed", L, 3, 4, []crypto.Hash{p[1], p[0]}, R)
	}
	add("on the empty tree (tree_test.go:70 root): leaf_index 0, tree_size 0, empty path", merkle.HashEmptyTree(), 0, 0, []crypto.Hash{}, wants[0])
	add("on TestGetRootHash/TestInclusion size 5 (tree_test.go:62-118): leaf 4 at size 5 with an empty path and root hashes[4] (right-edge truncation)",
		leaves[4], 4, 5, []crypto.Hash{}, leaves[4])
	add("on TestGetRootHash/TestInclusion size 5 (tree_test.go:62-118): leaf 2 at size 5 with the size 4 path [hashes[3], h01] and root h0123 (truncation, chain equals the size 4 root)",
		leaves[2], 2, 5, []crypto.Hash{leaves[3], h01}, h0123)
	return out
}

// ---------------------------------------------------------------------------
// Output

func marshal(f *Fixture) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const usage = `usage: go run . -fixtures <path> [-write] [-ours <path>]
  -fixtures <path>  the sigsum-go fixture file, vectors/interop/sigsum-go.json (required)
  -write            regenerate the fixture file from the upstream literals and sigsum-go, then check it
  -ours <path>      also check the library's own known answers, vectors/merkle.json, with sigsum-go
It prints "OK fixtures sigsum.org/sigsum-go@v0.14.1: <counts>" and, with -ours,
"OK ours sigsum.org/sigsum-go@v0.14.1: <counts>", or one FAIL line per problem,
and exits 1 on any failure.
`

// maxFailLines caps the FAIL lines printed per phase; one more line counts
// the rest.
const maxFailLines = 50

// oneLine folds a message onto a single line, so that every problem is
// exactly one output line.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	parts := strings.Split(s, "\n")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, "; ")
}

// report prints a phase's result: its OK line, or one FAIL line per problem.
// It returns the phase's exit status.
func report(out io.Writer, phase, summary string, fails []string) int {
	if len(fails) == 0 {
		fmt.Fprintf(out, "OK %s %s@%s: %s\n", phase, implementation, version, oneLine(summary))
		return 0
	}
	for i, s := range fails {
		if i == maxFailLines {
			fmt.Fprintf(out, "FAIL %s %d more problems not shown\n", phase, len(fails)-maxFailLines)
			break
		}
		fmt.Fprintf(out, "FAIL %s %s\n", phase, oneLine(s))
	}
	return 1
}

// guarded runs one phase. A panic in it becomes one failure of that phase.
func guarded(phase func() (string, []string)) (summary string, fails []string) {
	defer func() {
		if r := recover(); r != nil {
			summary = ""
			fails = append(fails, fmt.Sprintf("internal error: %v", r))
		}
	}()
	return phase()
}

type options struct {
	fixtures, ours string
	oursSet, write bool
}

// parseFlags reads the command line. flag.ErrHelp means -h or -help.
func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("sigsum-go", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.fixtures, "fixtures", "", "")
	fs.BoolVar(&o.write, "write", false, "")
	fs.StringVar(&o.ours, "ours", "", "")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q; the program takes flags only", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	o.oursSet = set["ours"]
	switch {
	case !set["fixtures"]:
		return o, errors.New("-fixtures <path> is required")
	case o.fixtures == "":
		return o, errors.New("-fixtures needs a non-empty path")
	case strings.HasPrefix(o.fixtures, "-"):
		return o, fmt.Errorf("-fixtures needs a path, not the flag-like %q", o.fixtures)
	case o.oursSet && o.ours == "":
		return o, errors.New("-ours needs a non-empty path")
	case o.oursSet && strings.HasPrefix(o.ours, "-"):
		return o, fmt.Errorf("-ours needs a path, not the flag-like %q", o.ours)
	}
	return o, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole program. It never panics and never exits 2: a bad flag,
// a stray argument, an unreadable or malformed file and any internal error
// all become FAIL lines and exit status 1. Only -h and -help write to
// stderr, and they exit 0.
func run(args []string, out, errOut io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(out, "FAIL fixtures internal error: %s\n", oneLine(fmt.Sprint(r)))
			code = 1
		}
	}()

	o, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(errOut, usage)
		return 0
	}
	if err != nil {
		fmt.Fprintf(out, "FAIL usage: %s\n", oneLine(err.Error()))
		return 1
	}

	summary, fails := guarded(func() (string, []string) {
		if o.write {
			f, err := build()
			if err != nil {
				return "", []string{fmt.Sprintf("build: %v", err)}
			}
			b, err := marshal(f)
			if err != nil {
				return "", []string{fmt.Sprintf("marshal: %v", err)}
			}
			if err := os.WriteFile(o.fixtures, b, 0o644); err != nil {
				return "", []string{fmt.Sprintf("write: %v", err)}
			}
		}
		return check(o.fixtures)
	})
	code = report(out, "fixtures", summary, fails)
	if o.oursSet {
		summary, fails := guarded(func() (string, []string) {
			return checkOurs(o.ours)
		})
		code |= report(out, "ours", summary, fails)
	}
	return code
}
