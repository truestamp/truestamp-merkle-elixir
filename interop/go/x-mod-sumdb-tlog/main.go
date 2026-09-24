// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
// Contains upstream literals from golang.org/x/mod@v0.41.0 in fixture entry
// names: the record texts, hashes and test names of sumdb/client_test.go and
// sumdb/tlog/note_test.go, and the TestTree leaf format "leaf %d" and failure
// text "corrupt proof hash #%d" of sumdb/tlog/tlog_test.go. BSD-3-Clause,
// Copyright 2009 The Go Authors; see LICENSE-golang-x-mod and NOTICE.

// Command x-mod-sumdb-tlog builds and checks the fixture file of
// golang.org/x/mod (package sumdb/tlog) known answers, and optionally checks
// the truestamp_merkle library's own vectors with the same implementation. It
// lives at interop/go/x-mod-sumdb-tlog/ in the truestamp_merkle repository,
// and its fixture at vectors/interop/x-mod-sumdb-tlog.json. From this
// directory:
//
//	go run . -fixtures ../../../vectors/interop/x-mod-sumdb-tlog.json
//	    check the fixture file
//	go run . -fixtures ../../../vectors/interop/x-mod-sumdb-tlog.json -write
//	    regenerate the fixture file from the upstream literals and tlog, then
//	    check it
//	go run . -fixtures ../../../vectors/interop/x-mod-sumdb-tlog.json -ours ../../../vectors/merkle.json
//	    also check the library's vectors/merkle.json
//
// -fixtures is required. The check confirms, entry by entry, that
// golang.org/x/mod/sumdb/tlog reproduces every value with its own functions
// (RecordHash, NodeHash, StoredHashes, StoredHashesForRecordHash, TreeHash,
// ProveRecord, CheckRecord, and TileHashReader for the sumdb client's
// lookups). It also regenerates the fixture from the upstream literals in
// upstream.go and requires the file to be byte-identical, so nothing can be
// missing, added, or edited by hand. -ours is described in ours.go.
//
// On success it prints one line "OK fixtures golang.org/x/mod@v0.41.0:
// <counts>", with -ours a second line "OK ours golang.org/x/mod@v0.41.0:
// <counts>", and exits 0. Each problem is one line starting "FAIL fixtures "
// or "FAIL ours ", and the exit status is 1. A bad command line (an unknown
// flag, a flag without its value or with an empty one, a repeated flag, a
// positional argument, or no -fixtures) is one line "FAIL usage: <reason>"
// and exit status 1. -h and -help print the usage to stderr and exit 0. A
// panic in any phase becomes one FAIL line of that phase. It reads no file
// except the -fixtures and -ours paths.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

const (
	modulePath     = "golang.org/x/mod"
	implementation = modulePath // the schema's "implementation" is the module path
	moduleVersion  = "v0.41.0"
	moduleLicense  = "BSD-3-Clause"
)

type HashCheck struct {
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	InputHex *string `json:"input_hex,omitempty"`
	Left     *string `json:"left,omitempty"`
	Right    *string `json:"right,omitempty"`
	Hash     string  `json:"hash"`
}

// LeafDataRule is the schema's rule form for large trees. Every tree here
// lists its leaves, so it is always null.
type LeafDataRule struct {
	Encoding string `json:"encoding"`
	First    int64  `json:"first"`
}

type Tree struct {
	Name         string        `json:"name"`
	LeafData     []string      `json:"leaf_data"`
	LeafHashes   []string      `json:"leaf_hashes"`
	LeafDataRule *LeafDataRule `json:"leaf_data_rule"`
	TreeSize     int64         `json:"tree_size"`
	Root         string        `json:"root"`
}

type Inclusion struct {
	Name                string   `json:"name"`
	LeafHash            string   `json:"leaf_hash"`
	LeafIndex           int64    `json:"leaf_index"`
	TreeSize            int64    `json:"tree_size"`
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

// storage is a tlog.HashReader over the stored-hash layout tlog writes.
type storage []tlog.Hash

func (s storage) ReadHashes(ix []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(ix))
	for i, x := range ix {
		if x < 0 || x >= int64(len(s)) {
			return nil, fmt.Errorf("stored hash index %d out of range (have %d)", x, len(s))
		}
		out[i] = s[x]
	}
	return out, nil
}

// fromLeafHashes appends leaves by hash, the leaf-hash-level entry point.
func fromLeafHashes(leaves []tlog.Hash) (storage, error) {
	var s storage
	for i, h := range leaves {
		hs, err := tlog.StoredHashesForRecordHash(int64(i), h, s)
		if err != nil {
			return nil, err
		}
		s = append(s, hs...)
	}
	return s, nil
}

// fromLeafData appends leaves by data, the path upstream tests use.
func fromLeafData(data [][]byte) (storage, error) {
	var s storage
	for i, d := range data {
		hs, err := tlog.StoredHashes(int64(i), d, s)
		if err != nil {
			return nil, err
		}
		s = append(s, hs...)
	}
	return s, nil
}

// tlogMaxTreeSize is the largest tree size tlog can work with. Above 2^62,
// maxpow2 (sumdb/tlog/tlog.go:70-78) never returns, since 1<<63 is negative
// and 1<<64 is 0 in int64, so CheckRecord, ProveRecord and TreeHash do not
// return on any proof that splits such a range.
const tlogMaxTreeSize = 1 << 62

// tlogReturns reports whether tlog.CheckRecord(p, t, th, n, h) returns: it
// answers at once when n is out of range or p is empty, and otherwise needs
// t <= 2^62. Every call on a size read from a file is gated by it, so a
// hostile file cannot hang the program.
func tlogReturns(t, n int64, pathLen int) bool {
	return t <= tlogMaxTreeSize || n < 0 || n >= t || pathLen == 0
}

func hx(h tlog.Hash) string { return hex.EncodeToString(h[:]) }
func hxb(b []byte) string   { return hex.EncodeToString(b) }
func sp(s string) *string   { return &s }
func mustB64(s string) tlog.Hash {
	h, err := tlog.ParseHash(s)
	if err != nil {
		panic(fmt.Sprintf("bad upstream base64 hash %q: %v", s, err))
	}
	return h
}

func parseHex(s string) (tlog.Hash, error) {
	var h tlog.Hash
	if s != strings.ToLower(s) {
		return h, fmt.Errorf("hash %q is not lowercase hex", s)
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != tlog.HashSize {
		return h, fmt.Errorf("hash %q is not 32 bytes of hex", s)
	}
	copy(h[:], b)
	return h, nil
}

func parseHexData(s string) ([]byte, error) {
	if s != strings.ToLower(s) {
		return nil, fmt.Errorf("data %q is not lowercase hex", s)
	}
	return hex.DecodeString(s)
}

// ---------- generation ----------

type publishedTree struct {
	name    string
	records []string
	rootB64 string
}

func publishedTrees() []publishedTree {
	base := []string{clientRecord0, clientRecord1, clientRecord2, clientRecord3}
	with := func(extra ...string) []string {
		return append(append([]string{}, base...), extra...)
	}
	return []publishedTree{
		{
			name:    "published: sumdb/client_test.go TestClientFork, newTestClient records 0..3, tree_size 4 (proof of misbehavior line 4 at client_test.go:138, the MTH(D[0:4]) element of ProveTree(6, 5))",
			records: base,
			rootB64: forkProof2B64,
		},
		{
			name:    "published: sumdb/client_test.go TestClientFork, tc old database tree_size 5 (client_test.go:123)",
			records: with(tcRecord4),
			rootB64: forkOldTree5RootB64,
		},
		{
			name:    "published: sumdb/client_test.go TestClientFork, tc2 tree_size 5 (proof of misbehavior line 1 at client_test.go:135, prefix asserted at client_test.go:148)",
			records: with(tc2Record4),
			rootB64: forkTc2Tree5RootB64,
		},
		{
			name:    "published: sumdb/client_test.go TestClientFork, tc2 new database tree_size 6 (client_test.go:130)",
			records: with(tc2Record4, tc2Record5),
			rootB64: forkNewTree6RootB64,
		},
	}
}

func buildTree(name string, records [][]byte) (Tree, storage, error) {
	var leafHashes []tlog.Hash
	t := Tree{Name: name, TreeSize: int64(len(records))}
	t.LeafData = make([]string, 0, len(records))
	t.LeafHashes = make([]string, 0, len(records))
	for _, r := range records {
		h := tlog.RecordHash(r)
		leafHashes = append(leafHashes, h)
		t.LeafData = append(t.LeafData, hxb(r))
		t.LeafHashes = append(t.LeafHashes, hx(h))
	}
	s, err := fromLeafData(records)
	if err != nil {
		return t, nil, err
	}
	root, err := tlog.TreeHash(t.TreeSize, s)
	if err != nil {
		return t, nil, err
	}
	s2, err := fromLeafHashes(leafHashes)
	if err != nil {
		return t, nil, err
	}
	root2, err := tlog.TreeHash(t.TreeSize, s2)
	if err != nil {
		return t, nil, err
	}
	if root != root2 {
		return t, nil, fmt.Errorf("%s: StoredHashes and StoredHashesForRecordHash disagree", name)
	}
	t.Root = hx(root)
	return t, s, nil
}

// expectFunc gives the upstream_expectation of the proof of leaf m, and a
// suffix for the case name that says which upstream lines assert it.
type expectFunc func(m int64) (expectation, suffix string)

func alwaysValid(int64) (string, string) { return "valid", "" }

// fromClient takes the expectation of each proof of tree t from the replayed
// sumdb client lookups: "valid" or "invalid" where a lookup settles it, else
// "none".
func fromClient(v clientVerdicts, t Tree) expectFunc {
	return func(m int64) (string, string) {
		root, err := parseHex(t.Root)
		if err != nil {
			return "none", ""
		}
		e, where := v.expectation(t.TreeSize, root, m)
		if e == "none" {
			return e, ""
		}
		return e, assertionSuffix(where)
	}
}

func proofCases(t Tree, s storage, prefix string, expect expectFunc, corrupt bool) ([]Inclusion, error) {
	var out []Inclusion
	root, _ := parseHex(t.Root)
	for m := int64(0); m < t.TreeSize; m++ {
		leaf, _ := parseHex(t.LeafHashes[m])
		p, err := tlog.ProveRecord(t.TreeSize, m, s)
		if err != nil {
			return nil, fmt.Errorf("ProveRecord(%d, %d): %v", t.TreeSize, m, err)
		}
		expectation, suffix := expect(m)
		c := Inclusion{
			Name:                fmt.Sprintf("%s tree_size %d leaf_index %d, ProveRecord path%s", prefix, t.TreeSize, m, suffix),
			LeafHash:            hx(leaf),
			LeafIndex:           m,
			TreeSize:            t.TreeSize,
			Path:                pathHex(p),
			Root:                hx(root),
			Valid:               tlog.CheckRecord(p, t.TreeSize, root, m, leaf) == nil,
			UpstreamExpectation: expectation,
		}
		out = append(out, c)
		if !corrupt {
			continue
		}
		// Upstream corruption, tlog_test.go:142-148, applied to a copy.
		for k := range p {
			q := append(tlog.RecordProof{}, p...)
			q[k][0] ^= 1
			out = append(out, Inclusion{
				Name:                fmt.Sprintf("%s tree_size %d leaf_index %d, upstream corruption \"corrupt proof hash #%d\" (p[%d][0] ^= 1, tlog_test.go:143)", prefix, t.TreeSize, m, k, k),
				LeafHash:            hx(leaf),
				LeafIndex:           m,
				TreeSize:            t.TreeSize,
				Path:                pathHex(q),
				Root:                hx(root),
				Valid:               tlog.CheckRecord(q, t.TreeSize, root, m, leaf) == nil,
				UpstreamExpectation: "invalid",
			})
		}
	}
	return out, nil
}

func pathHex(p tlog.RecordProof) []string {
	out := make([]string, 0, len(p))
	for _, h := range p {
		out = append(out, hx(h))
	}
	return out
}

func generate() (*Fixture, error) {
	f := &Fixture{
		Implementation: implementation,
		Version:        moduleVersion,
		License:        moduleLicense,
		Sources:        sources,
		Deviations:     []string{},
		Discrepancies:  []string{},
	}

	// Empty tree.
	empty, err := tlog.TreeHash(0, nil)
	if err != nil {
		return nil, fmt.Errorf("TreeHash(0, nil): %v", err)
	}
	if empty != tlog.Hash(upstreamEmptyHash) || empty != tlog.Hash(sha256.Sum256(nil)) {
		return nil, fmt.Errorf("TreeHash(0) = %s, want tlog.go emptyHash and SHA-256(\"\")", hx(empty))
	}
	f.EmptyRoot = sp(hx(empty))

	// Hash checks.
	helloHash := tlog.RecordHash([]byte(noteTestLeafData))
	if helloHash != mustB64(noteTestLeafHashB64) {
		return nil, fmt.Errorf("RecordHash(%q) = %v, want %s", noteTestLeafData, helloHash, noteTestLeafHashB64)
	}
	tc2Leaf4 := tlog.RecordHash([]byte(tc2Record4))
	if tc2Leaf4 != mustB64(forkProof0B64) {
		return nil, fmt.Errorf("RecordHash(tc2 record 4) = %v, want %s", tc2Leaf4, forkProof0B64)
	}
	tc2Leaf5 := tlog.RecordHash([]byte(tc2Record5))
	if tc2Leaf5 != mustB64(forkProof1B64) {
		return nil, fmt.Errorf("RecordHash(tc2 record 5) = %v, want %s", tc2Leaf5, forkProof1B64)
	}
	tcLeaf4 := tlog.RecordHash([]byte(tcRecord4))
	root4 := mustB64(forkProof2B64)
	n5tc2 := tlog.NodeHash(root4, tc2Leaf4)
	if n5tc2 != mustB64(forkTc2Tree5RootB64) {
		return nil, fmt.Errorf("NodeHash(root4, tc2 leaf 4) = %v, want %s", n5tc2, forkTc2Tree5RootB64)
	}
	n5tc := tlog.NodeHash(root4, tcLeaf4)
	if n5tc != mustB64(forkOldTree5RootB64) {
		return nil, fmt.Errorf("NodeHash(root4, tc leaf 4) = %v, want %s", n5tc, forkOldTree5RootB64)
	}
	n45 := tlog.NodeHash(tc2Leaf4, tc2Leaf5)
	n6 := tlog.NodeHash(root4, n45)
	if n6 != mustB64(forkNewTree6RootB64) {
		return nil, fmt.Errorf("NodeHash(root4, NodeHash(tc2 leaf 4, tc2 leaf 5)) = %v, want %s", n6, forkNewTree6RootB64)
	}
	f.HashChecks = []HashCheck{
		{
			Name:     "published: sumdb/tlog/note_test.go:14-15 TestFormatTree golden hash TszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0= = RecordHash(\"hello world\")",
			Kind:     "leaf",
			InputHex: sp(hxb([]byte(noteTestLeafData))),
			Hash:     hx(helloHash),
		},
		{
			Name:     "published: sumdb/client_test.go:136 proof of misbehavior line 2 = RecordHash(tc2 record 4 \"rsc.io/pkg1 v1.5.3 h1:hash!=\\n\", client_test.go:105-106)",
			Kind:     "leaf",
			InputHex: sp(hxb([]byte(tc2Record4))),
			Hash:     hx(tc2Leaf4),
		},
		{
			Name:     "published: sumdb/client_test.go:137 proof of misbehavior line 3 = RecordHash(tc2 record 5 \"rsc.io/pkg1 v1.5.4 h1:hash!=\\n\", client_test.go:107-108)",
			Kind:     "leaf",
			InputHex: sp(hxb([]byte(tc2Record5))),
			Hash:     hx(tc2Leaf5),
		},
		{
			Name:  "published: sumdb/client_test.go tc2 tree_size 5 root (line 135) = NodeHash(tree_size 4 root (line 138), tc2 leaf 4 (line 136)); all three values published",
			Kind:  "node",
			Left:  sp(hx(root4)),
			Right: sp(hx(tc2Leaf4)),
			Hash:  hx(n5tc2),
		},
		{
			Name:     "derived: RecordHash(tc record 4 \"rsc.io/pkg1 v1.5.2 h1:hash!=\\n\", sumdb/client_test.go:99-100)",
			Kind:     "leaf",
			InputHex: sp(hxb([]byte(tcRecord4))),
			Hash:     hx(tcLeaf4),
		},
		{
			Name:  "published: sumdb/client_test.go tc old database tree_size 5 root (line 123) = NodeHash(tree_size 4 root (line 138), derived tc leaf 4)",
			Kind:  "node",
			Left:  sp(hx(root4)),
			Right: sp(hx(tcLeaf4)),
			Hash:  hx(n5tc),
		},
		{
			Name:  "derived: NodeHash(tc2 leaf 4 (sumdb/client_test.go:136), tc2 leaf 5 (sumdb/client_test.go:137)), inputs published",
			Kind:  "node",
			Left:  sp(hx(tc2Leaf4)),
			Right: sp(hx(tc2Leaf5)),
			Hash:  hx(n45),
		},
		{
			Name:  "published: sumdb/client_test.go tc2 new database tree_size 6 root (line 130) = NodeHash(tree_size 4 root (line 138), derived NodeHash(tc2 leaf 4, tc2 leaf 5))",
			Kind:  "node",
			Left:  sp(hx(root4)),
			Right: sp(hx(n45)),
			Hash:  hx(n6),
		},
	}

	// Replay the sumdb client lookups of client_test.go over the upstream
	// records with tlog (clientpath.go); what they settle is the
	// upstream_expectation of the client proofs below.
	src, err := clientSourceFromRecords(clientLogRecords())
	if err != nil {
		return nil, err
	}
	verdicts, err := replayClients(src)
	if err != nil {
		return nil, fmt.Errorf("replaying the client lookups over the upstream records: %v", err)
	}

	// Published trees.
	type built struct {
		tree Tree
		s    storage
	}
	var pub []built
	for _, pt := range publishedTrees() {
		var recs [][]byte
		for _, r := range pt.records {
			recs = append(recs, []byte(r))
		}
		t, s, err := buildTree(pt.name, recs)
		if err != nil {
			return nil, err
		}
		if t.Root != hx(mustB64(pt.rootB64)) {
			return nil, fmt.Errorf("%s: TreeHash = %s, want published %s", pt.name, t.Root, pt.rootB64)
		}
		f.Trees = append(f.Trees, t)
		pub = append(pub, built{t, s})
	}

	// Generated trees, TestTree scheme: sizes 1..16 and the largest upstream
	// size, 100. extraChecks covers all of 1..100 against the RFC reference.
	var all [][]byte
	var gen []built
	for i := int64(0); i < testTreeMaxSize; i++ {
		all = append(all, fmt.Appendf(nil, testTreeLeafFormat, i))
		size := i + 1
		if size > testTreeProofMaxSize && size != testTreeMaxSize {
			continue
		}
		t, s, err := buildTree(testTreeName(size), all)
		if err != nil {
			return nil, err
		}
		f.Trees = append(f.Trees, t)
		gen = append(gen, built{t, s})
	}

	// Inclusion: every proof over each published tree (no upstream assertion
	// on these proofs), then every proof and every upstream corruption for
	// TestTree sizes 1..16 (upstream asserts valid, then invalid).
	for i, b := range pub {
		label := []string{
			"generated: ProveRecord over published client_test.go TestClientFork tree_size 4 (newTestClient),",
			"generated: ProveRecord over published client_test.go TestClientFork tc old database,",
			"generated: ProveRecord over published client_test.go TestClientFork tc2 tree_size 5,",
			"generated: ProveRecord over published client_test.go TestClientFork tc2 new database,",
		}[i]
		cs, err := proofCases(b.tree, b.s, label, fromClient(verdicts, b.tree), false)
		if err != nil {
			return nil, err
		}
		f.Inclusion = append(f.Inclusion, cs...)
	}
	for _, b := range gen {
		if b.tree.TreeSize > testTreeProofMaxSize {
			break
		}
		cs, err := proofCases(b.tree, b.s, testTreeCasePrefix, alwaysValid, true)
		if err != nil {
			return nil, err
		}
		f.Inclusion = append(f.Inclusion, cs...)
	}

	// newTestClient's starting tree (client_test.go:306, signTree(1)) and its
	// one proof, the valid counterpart of the TestClientBadTiles case below.
	cst, css, err := buildTree(clientStartTreeName, [][]byte{[]byte(clientRecord0)})
	if err != nil {
		return nil, err
	}
	if cst.TreeSize != clientStartTreeSize {
		return nil, fmt.Errorf("newTestClient starting tree has size %d, want %d", cst.TreeSize, clientStartTreeSize)
	}
	f.Trees = append(f.Trees, cst)
	cs, err := proofCases(cst, css, clientStartProofPrefix, fromClient(verdicts, cst), false)
	if err != nil {
		return nil, err
	}
	f.Inclusion = append(f.Inclusion, cs...)

	// TestClientBadTiles "Bad starting tree hash" (client_test.go:83-92): the
	// same leaf at index 0 of a tree of size 1, with the all-zero root. The
	// replayed client rejects it, as upstream requires.
	leaf0 := tlog.RecordHash([]byte(clientRecord0))
	if e, _ := verdicts.expectation(badStartTreeSize, badStartTreeHash, 0); e != "invalid" {
		return nil, fmt.Errorf("the replayed client gives %q for the bad starting tree, upstream requires a rejection", e)
	}
	f.Inclusion = append(f.Inclusion, Inclusion{
		Name:                badTilesName,
		LeafHash:            hx(leaf0),
		LeafIndex:           0,
		TreeSize:            badStartTreeSize,
		Path:                []string{},
		Root:                hx(badStartTreeHash),
		Valid:               tlog.CheckRecord(tlog.RecordProof{}, badStartTreeSize, badStartTreeHash, 0, leaf0) == nil,
		UpstreamExpectation: "invalid",
	})

	// The size 0 tree.
	zt, _, err := buildTree(emptyTreeName, [][]byte{})
	if err != nil {
		return nil, err
	}
	if zt.Root != hx(tlog.Hash(upstreamEmptyHash)) {
		return nil, fmt.Errorf("TreeHash(0) = %s, want the emptyHash literal", zt.Root)
	}
	f.Trees = append(f.Trees, zt)

	// Edge cases over the TestTree leaf data.
	var seq []tlog.Hash
	for i := int64(0); i < testTreeMaxSize; i++ {
		seq = append(seq, tlog.RecordHash(fmt.Appendf(nil, testTreeLeafFormat, i)))
	}
	edges, meta, err := edgeCases(seq)
	if err != nil {
		return nil, err
	}
	f.Inclusion = append(f.Inclusion, edges...)

	// newTestClient's signed trees of size 2 and 3, and the size 5 tree of
	// TestRejectUnauthenticatedLines, with every proof over them.
	for _, ct := range extraClientTrees() {
		var recs [][]byte
		for _, r := range ct.records {
			recs = append(recs, []byte(r))
		}
		t, s, err := buildTree(ct.name, recs)
		if err != nil {
			return nil, err
		}
		f.Trees = append(f.Trees, t)
		cs, err := proofCases(t, s, ct.proofPrefix, fromClient(verdicts, t), false)
		if err != nil {
			return nil, err
		}
		f.Inclusion = append(f.Inclusion, cs...)
	}
	for _, list := range []map[statement][]string{verdicts.valid, verdicts.invalid} {
		for k := range list {
			n := 0
			for _, c := range f.Inclusion {
				if c.TreeSize == k.size && c.Root == hx(k.root) && c.LeafIndex == k.id && !strings.Contains(c.Name, edgeTag) && !strings.HasPrefix(c.Name, testTreeCasePrefix) {
					n++
				}
			}
			if n != 1 {
				return nil, fmt.Errorf("the client statement tree_size %d root %s leaf %d has %d cases, want 1", k.size, hx(k.root), k.id, n)
			}
		}
	}

	// The RFC 9162 section 2.1.3.2 answer for every case. Where tlog differs,
	// rfc9162_valid carries the RFC answer and the case is listed under
	// deviations and discrepancies.
	for i := range f.Inclusion {
		c := &f.Inclusion[i]
		r, err := rfcVerifyCase(*c)
		if err != nil {
			return nil, err
		}
		if r != c.Valid {
			rv := r
			c.RFC9162Valid = &rv
			f.Deviations = append(f.Deviations, rfcDeviation(*c))
		}
	}
	for _, c := range f.Inclusion {
		f.Discrepancies = append(f.Discrepancies, caseDiscrepancies(c)...)
	}
	f.Notes = buildNotes(trapCounts(edges, meta), len(edges), entryCounts(f))
	return f, nil
}

// clientLogRecords are the record texts each client test log serves, in order.
func clientLogRecords() map[clientLog][]string {
	base := []string{clientRecord0, clientRecord1, clientRecord2, clientRecord3}
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }
	return map[clientLog][]string{
		logTest:   base,
		logTc:     with(tcRecord4, tcRecord5),
		logTc2:    with(tc2Record4, tc2Record5),
		logUnauth: with(unauthRecord4),
	}
}

// clientSourceFromRecords hashes each log's records, and hashes the tree of
// every size the log reaches, as signTree does (client_test.go:414-426).
func clientSourceFromRecords(logs map[clientLog][]string) (clientSource, error) {
	src := clientSource{leaves: map[clientLog][]tlog.Hash{}, roots: map[clientLog]map[int64]tlog.Hash{}}
	for log, recs := range logs {
		var data [][]byte
		for _, r := range recs {
			data = append(data, []byte(r))
			src.leaves[log] = append(src.leaves[log], tlog.RecordHash([]byte(r)))
		}
		s, err := fromLeafData(data)
		if err != nil {
			return src, err
		}
		src.roots[log] = map[int64]tlog.Hash{}
		for n := int64(1); n <= int64(len(data)); n++ {
			h, err := tlog.TreeHash(n, s)
			if err != nil {
				return src, err
			}
			src.roots[log][n] = h
		}
	}
	return src, nil
}

// clientSourceFromFixture takes the same logs from the fixture's own trees:
// each log's leaf hashes from its largest tree, and its signed tree hashes
// from the trees of each size.
func clientSourceFromFixture(byName map[string]Tree) (clientSource, error) {
	pub := publishedTrees()
	specs := []struct {
		log    clientLog
		leaves string
		roots  map[int64]string
	}{
		{logTest, pub[0].name, map[int64]string{1: clientStartTreeName, 2: clientTree2Name, 3: clientTree3Name, 4: pub[0].name}},
		{logTc, pub[1].name, map[int64]string{1: clientStartTreeName, 5: pub[1].name}},
		{logTc2, pub[3].name, map[int64]string{1: clientStartTreeName, 5: pub[2].name, 6: pub[3].name}},
		{logUnauth, unauthTreeName, map[int64]string{1: clientStartTreeName, 5: unauthTreeName}},
	}
	src := clientSource{leaves: map[clientLog][]tlog.Hash{}, roots: map[clientLog]map[int64]tlog.Hash{}}
	for _, sp := range specs {
		t, ok := byName[sp.leaves]
		if !ok {
			return src, fmt.Errorf("no tree %q", sp.leaves)
		}
		for _, x := range t.LeafHashes {
			h, err := parseHex(x)
			if err != nil {
				return src, fmt.Errorf("tree %q: %v", sp.leaves, err)
			}
			src.leaves[sp.log] = append(src.leaves[sp.log], h)
		}
		src.roots[sp.log] = map[int64]tlog.Hash{}
		for size, name := range sp.roots {
			t, ok := byName[name]
			if !ok || t.TreeSize != size {
				return src, fmt.Errorf("no tree %q of size %d", name, size)
			}
			h, err := parseHex(t.Root)
			if err != nil {
				return src, fmt.Errorf("tree %q: %v", name, err)
			}
			src.roots[sp.log][size] = h
		}
	}
	return src, nil
}

type clientTreeSpec struct {
	name, proofPrefix string
	records           []string
}

func extraClientTrees() []clientTreeSpec {
	return []clientTreeSpec{
		{clientTree2Name, "generated: ProveRecord over client_test.go:400 newTestClient signTree(2),", []string{clientRecord0, clientRecord1}},
		{clientTree3Name, "generated: ProveRecord over client_test.go:400 newTestClient signTree(3),", []string{clientRecord0, clientRecord1, clientRecord2}},
		{unauthTreeName, "generated: ProveRecord over client_test.go:192-239 TestRejectUnauthenticatedLines tree_size 5,", []string{clientRecord0, clientRecord1, clientRecord2, clientRecord3, unauthRecord4}},
	}
}

// entryCounts counts the entries by their name prefix.
func entryCounts(f *Fixture) map[string]int {
	n := map[string]int{}
	if f.EmptyRoot != nil {
		n["published"]++
	}
	for _, h := range f.HashChecks {
		n[entryKind(h.Name)]++
		n["hash_checks_"+entryKind(h.Name)]++
	}
	for _, t := range f.Trees {
		n[entryKind(t.Name)]++
		n["trees_"+entryKind(t.Name)]++
	}
	for _, c := range f.Inclusion {
		n[entryKind(c.Name)]++
		n["inclusion_"+entryKind(c.Name)]++
		n["expect_"+c.UpstreamExpectation]++
	}
	return n
}

const testTreeNamePrefix = `generated: sumdb/tlog/tlog_test.go TestTree leaf data "leaf %d" (line 66), tree_size `

const testTreeCasePrefix = `generated: sumdb/tlog/tlog_test.go TestTree "leaf %d"`

func testTreeName(size int64) string { return fmt.Sprintf("%s%d", testTreeNamePrefix, size) }

const (
	clientStartTreeName    = "generated: sumdb/client_test.go:306 newTestClient signTree(1), the client's starting tree: tree_size 1 over record 0 (client_test.go:295-298)"
	clientStartProofPrefix = "generated: ProveRecord over client_test.go:306 newTestClient signTree(1),"
	badTilesName           = `published: sumdb/client_test.go:83-92 TestClientBadTiles "Bad starting tree hash looks like bad tiles": signed tree N 1 with Hash tlog.Hash{} (32 zero bytes, line 85) over newTestClient record 0 (lines 295-298); upstream requires the client to reject it (line 92, detected through tile hashes), here asked of tlog.CheckRecord with an empty path`
	emptyTreeName          = "published: sumdb/tlog/tlog.go:237-244 emptyHash, the tree_size 0 root that tlog.TreeHash(0, nil) returns (lines 250-253) and that TestEmptyTree (sumdb/tlog/tlog_test.go:272-280) asserts equals sha256.Sum256(nil)"
	clientTree2Name        = "generated: sumdb/client_test.go:400 newTestClient signTree(2), signed when record 1 is added (line 300) and served with the lookup of that record, which no test makes: tree_size 2 over records 0..1 (lines 295-302)"
	clientTree3Name        = "generated: sumdb/client_test.go:400 newTestClient signTree(3), signed when record 2 is added (line 303) and served with the rsc.io/sampler lookup, the tree TestClientLookup moves to (mustHaveLatest(3), line 31): tree_size 3 over records 0..2 (lines 295-305)"
	unauthTreeName         = "generated: sumdb/client_test.go:192-239 TestRejectUnauthenticatedLines, tlog.TreeHash(5) at line 209 over newTestClient records 0..3 (lines 295-309) and the record at line 195: tree_size 5"
)

func rfcDeviation(c Inclusion) string {
	return fmt.Sprintf("%s: tlog.CheckRecord returns valid=%v, RFC 9162 section 2.1.3.2 gives %v", c.Name, c.Valid, *c.RFC9162Valid)
}

func caseDiscrepancies(c Inclusion) []string {
	var out []string
	switch {
	case c.UpstreamExpectation == "valid" && !c.Valid:
		out = append(out, fmt.Sprintf("%s: upstream expects valid, tlog.CheckRecord rejects it", c.Name))
	case c.UpstreamExpectation == "invalid" && c.Valid:
		out = append(out, fmt.Sprintf("%s: upstream expects invalid, tlog.CheckRecord accepts it", c.Name))
	}
	if c.RFC9162Valid != nil {
		out = append(out, rfcDeviation(c))
	}
	return out
}

func encode(f *Fixture) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------- verification of a fixture file, entry by entry ----------

type checker struct {
	errs   []string
	checks int
}

func (c *checker) fail(format string, args ...any) {
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
}

func (c *checker) ok() { c.checks++ }

func verify(f *Fixture) (*checker, map[string]int) {
	c := &checker{}
	counts := map[string]int{}

	if f.Implementation != implementation {
		c.fail("implementation = %q, want the module path %q", f.Implementation, implementation)
	}
	if f.Version != linkedVersion() {
		c.fail("version = %q, but the linked %s is %q", f.Version, modulePath, linkedVersion())
	}
	if f.License != moduleLicense {
		c.fail("license = %q, want %q", f.License, moduleLicense)
	}

	// empty_root
	if f.EmptyRoot == nil {
		c.fail("empty_root is null, but upstream publishes one")
	} else if want, err := parseHex(*f.EmptyRoot); err != nil {
		c.fail("empty_root: %v", err)
	} else if got, err := tlog.TreeHash(0, nil); err != nil || got != want {
		c.fail("empty_root: tlog.TreeHash(0, nil) = %s, %v; fixture has %s", hx(got), err, *f.EmptyRoot)
	} else if got != tlog.Hash(sha256.Sum256(nil)) {
		c.fail("empty_root is not SHA-256(\"\")")
	} else {
		c.ok()
	}

	// hash_checks
	for _, h := range f.HashChecks {
		want, err := parseHex(h.Hash)
		if err != nil {
			c.fail("hash_check %q: %v", h.Name, err)
			continue
		}
		switch h.Kind {
		case "leaf":
			if h.InputHex == nil || h.Left != nil || h.Right != nil {
				c.fail("hash_check %q: leaf needs input_hex only", h.Name)
				continue
			}
			in, err := parseHexData(*h.InputHex)
			if err != nil {
				c.fail("hash_check %q: %v", h.Name, err)
				continue
			}
			if got := tlog.RecordHash(in); got != want {
				c.fail("hash_check %q: tlog.RecordHash = %s, fixture has %s", h.Name, hx(got), h.Hash)
				continue
			}
		case "node":
			if h.InputHex != nil || h.Left == nil || h.Right == nil {
				c.fail("hash_check %q: node needs left and right only", h.Name)
				continue
			}
			l, err1 := parseHex(*h.Left)
			r, err2 := parseHex(*h.Right)
			if err1 != nil || err2 != nil {
				c.fail("hash_check %q: bad left/right", h.Name)
				continue
			}
			if got := tlog.NodeHash(l, r); got != want {
				c.fail("hash_check %q: tlog.NodeHash = %s, fixture has %s", h.Name, hx(got), h.Hash)
				continue
			}
		default:
			c.fail("hash_check %q: unknown kind %q", h.Name, h.Kind)
			continue
		}
		c.ok()
		counts["hash_checks"]++
	}

	// trees
	type treeKey struct {
		size int64
		root string
	}
	treeStore := map[treeKey]storage{}
	treeLeaves := map[treeKey][]string{}
	byName := map[string]Tree{}
	for _, t := range f.Trees {
		byName[t.Name] = t
		if t.LeafDataRule != nil {
			c.fail("tree %q: leaf_data_rule is set, but every tree here lists its leaves", t.Name)
			continue
		}
		if int64(len(t.LeafHashes)) != t.TreeSize || t.LeafHashes == nil {
			c.fail("tree %q: %d leaf_hashes for tree_size %d", t.Name, len(t.LeafHashes), t.TreeSize)
			continue
		}
		want, err := parseHex(t.Root)
		if err != nil {
			c.fail("tree %q: %v", t.Name, err)
			continue
		}
		var leaves []tlog.Hash
		bad := false
		for _, s := range t.LeafHashes {
			h, err := parseHex(s)
			if err != nil {
				c.fail("tree %q: %v", t.Name, err)
				bad = true
				break
			}
			leaves = append(leaves, h)
		}
		if bad {
			continue
		}
		s, err := fromLeafHashes(leaves)
		if err != nil {
			c.fail("tree %q: StoredHashesForRecordHash: %v", t.Name, err)
			continue
		}
		got, err := tlog.TreeHash(t.TreeSize, s)
		if err != nil || got != want {
			c.fail("tree %q: tlog.TreeHash over leaf hashes = %s, %v; fixture has %s", t.Name, hx(got), err, t.Root)
			continue
		}
		if t.LeafData != nil {
			if len(t.LeafData) != len(t.LeafHashes) {
				c.fail("tree %q: %d leaf_data for %d leaf_hashes", t.Name, len(t.LeafData), len(t.LeafHashes))
				continue
			}
			var data [][]byte
			for i, d := range t.LeafData {
				b, err := parseHexData(d)
				if err != nil {
					c.fail("tree %q leaf %d: %v", t.Name, i, err)
					bad = true
					break
				}
				if tlog.RecordHash(b) != leaves[i] {
					c.fail("tree %q leaf %d: tlog.RecordHash(leaf_data) != leaf_hashes[%d]", t.Name, i, i)
					bad = true
					break
				}
				if strings.HasPrefix(t.Name, testTreeNamePrefix) && string(b) != fmt.Sprintf(testTreeLeafFormat, i) {
					c.fail("tree %q leaf %d: leaf_data is not the upstream TestTree data %q", t.Name, i, fmt.Sprintf(testTreeLeafFormat, i))
					bad = true
					break
				}
				data = append(data, b)
			}
			if bad {
				continue
			}
			sd, err := fromLeafData(data)
			if err != nil {
				c.fail("tree %q: StoredHashes: %v", t.Name, err)
				continue
			}
			if got, err := tlog.TreeHash(t.TreeSize, sd); err != nil || got != want {
				c.fail("tree %q: tlog.TreeHash over leaf data = %s, %v; fixture has %s", t.Name, hx(got), err, t.Root)
				continue
			}
		}
		k := treeKey{t.TreeSize, t.Root}
		treeStore[k] = s
		treeLeaves[k] = t.LeafHashes
		c.ok()
		counts["trees"]++
	}

	// The TestTree leaf hashes in order, from the fixture's size 100 tree; every
	// smaller TestTree tree must be a prefix of it.
	var seq []tlog.Hash
	if big, ok := byName[testTreeName(testTreeMaxSize)]; !ok {
		c.fail("no TestTree tree of size %d in the fixture", testTreeMaxSize)
	} else {
		for _, s := range big.LeafHashes {
			h, err := parseHex(s)
			if err != nil {
				break
			}
			seq = append(seq, h)
		}
		for n := int64(1); n <= testTreeProofMaxSize; n++ {
			t, ok := byName[testTreeName(n)]
			if !ok || int64(len(t.LeafHashes)) != n || int64(len(big.LeafHashes)) < n {
				c.fail("TestTree tree of size %d missing or malformed", n)
				continue
			}
			for i := range t.LeafHashes {
				if t.LeafHashes[i] != big.LeafHashes[i] {
					c.fail("TestTree tree of size %d is not a prefix of the size %d tree", n, testTreeMaxSize)
					break
				}
			}
		}
	}

	// Replay the sumdb client lookups over the fixture's own client trees. The
	// replay settles the upstream_expectation of every client proof.
	var verdicts clientVerdicts
	replayed := false
	if src, err := clientSourceFromFixture(byName); err != nil {
		c.fail("client lookups: %v", err)
	} else if verdicts, err = replayClients(src); err != nil {
		c.fail("client lookups replayed over the fixture's trees: %v", err)
	} else {
		replayed = true
		counts["client_replay_checks"] = verdicts.checks
		c.ok()
	}
	matched := map[statement]int{}

	// inclusion
	var discrepancies []string
	var edgeInFile []Inclusion
	for _, in := range f.Inclusion {
		leaf, err1 := parseHex(in.LeafHash)
		root, err2 := parseHex(in.Root)
		if err1 != nil || err2 != nil {
			c.fail("inclusion %q: bad leaf_hash or root", in.Name)
			continue
		}
		if in.Path == nil {
			c.fail("inclusion %q: path is null", in.Name)
			continue
		}
		var p tlog.RecordProof
		bad := false
		for _, s := range in.Path {
			h, err := parseHex(s)
			if err != nil {
				c.fail("inclusion %q: %v", in.Name, err)
				bad = true
				break
			}
			p = append(p, h)
		}
		if bad {
			continue
		}
		switch in.UpstreamExpectation {
		case "valid", "invalid", "none":
		default:
			c.fail("inclusion %q: upstream_expectation %q", in.Name, in.UpstreamExpectation)
			continue
		}
		if !tlogReturns(in.TreeSize, in.LeafIndex, len(p)) {
			c.fail("inclusion %q: tree_size %d is above 2^62, where tlog.CheckRecord does not return (maxpow2, sumdb/tlog/tlog.go:70-78)", in.Name, in.TreeSize)
			continue
		}
		gotValid := tlog.CheckRecord(p, in.TreeSize, root, in.LeafIndex, leaf) == nil
		if gotValid != in.Valid {
			c.fail("inclusion %q: tlog.CheckRecord valid=%v, fixture has valid=%v", in.Name, gotValid, in.Valid)
			continue
		}
		if replayed && !strings.Contains(in.Name, edgeTag) && !strings.HasPrefix(in.Name, testTreeCasePrefix) {
			want, _ := verdicts.expectation(in.TreeSize, root, in.LeafIndex)
			if in.UpstreamExpectation != want {
				c.fail("inclusion %q: upstream_expectation %q, but the replayed sumdb client lookups give %q", in.Name, in.UpstreamExpectation, want)
				continue
			}
			if want != "none" {
				matched[statement{in.TreeSize, root, in.LeafIndex}]++
				counts["client_"+want]++
			}
		}
		discrepancies = append(discrepancies, caseDiscrepancies(in)...)
		kind := entryKind(in.Name)

		switch {
		case strings.Contains(in.Name, edgeTag):
			// Checked as a set below, against a re-derivation with tlog.
			edgeInFile = append(edgeInFile, in)
		case in.Name == badTilesName:
			// client_test.go:83-92: leaf 0 of the newTestClient starting tree,
			// tree_size 1, empty path, the all-zero root.
			st, ok := byName[clientStartTreeName]
			switch {
			case !ok || len(st.LeafHashes) != 1:
				c.fail("inclusion %q: the newTestClient starting tree is missing", in.Name)
				continue
			case in.LeafHash != st.LeafHashes[0] || in.LeafIndex != 0 || in.TreeSize != badStartTreeSize || len(p) != 0:
				c.fail("inclusion %q: not record 0 at index 0 of a size %d tree with an empty path", in.Name, badStartTreeSize)
				continue
			case root != badStartTreeHash || in.UpstreamExpectation != "invalid":
				c.fail("inclusion %q: root is not tlog.Hash{} or expectation is not invalid", in.Name)
				continue
			}
		default:
			// Prover check: the case must come from a fixture tree, and the
			// path must be tlog.ProveRecord's path, or that path with exactly
			// the upstream corruption applied to the element the name says.
			k := treeKey{in.TreeSize, in.Root}
			s, found := treeStore[k]
			if !found {
				c.fail("inclusion %q: no tree in the fixture with tree_size %d and this root", in.Name, in.TreeSize)
				continue
			}
			if in.LeafIndex < 0 || in.LeafIndex >= in.TreeSize || treeLeaves[k][in.LeafIndex] != in.LeafHash {
				c.fail("inclusion %q: leaf_hash is not leaf %d of its tree", in.Name, in.LeafIndex)
				continue
			}
			want, err := tlog.ProveRecord(in.TreeSize, in.LeafIndex, s)
			if err != nil {
				c.fail("inclusion %q: tlog.ProveRecord: %v", in.Name, err)
				continue
			}
			if in.Valid {
				if !equalProof(p, want) {
					c.fail("inclusion %q: path differs from tlog.ProveRecord", in.Name)
					continue
				}
			} else {
				if len(p) != len(want) {
					c.fail("inclusion %q: corrupted path length %d, ProveRecord length %d", in.Name, len(p), len(want))
					continue
				}
				diff := -1
				for i := range p {
					if p[i] != want[i] {
						if diff >= 0 {
							diff = -2
							break
						}
						diff = i
					}
				}
				if diff < 0 {
					c.fail("inclusion %q: invalid case must differ from ProveRecord in exactly one element", in.Name)
					continue
				}
				w := want[diff]
				w[0] ^= 1
				if p[diff] != w || !strings.Contains(in.Name, fmt.Sprintf("\"corrupt proof hash #%d\"", diff)) {
					c.fail("inclusion %q: element %d is not the upstream p[k][0] ^= 1 corruption named in the case", in.Name, diff)
					continue
				}
			}
		}
		if in.Valid {
			counts["inclusion_valid"]++
		} else {
			counts["inclusion_invalid"]++
		}
		counts["inclusion_"+kind]++
		counts[kind]++
		c.ok()
	}

	if replayed {
		for _, list := range []map[statement][]string{verdicts.valid, verdicts.invalid} {
			for k := range list {
				if matched[k] != 1 {
					c.fail("client lookups: the statement tree_size %d root %s leaf %d has %d cases in the fixture, want 1", k.size, hx(k.root), k.id, matched[k])
				}
			}
		}
	}

	// Edge cases: re-derive the whole set from the fixture's TestTree leaf
	// hashes with tlog and require the file to hold exactly that, in order.
	if seq != nil {
		want, _, err := edgeCases(seq)
		switch {
		case err != nil:
			c.fail("edge cases: %v", err)
		case len(want) != len(edgeInFile):
			c.fail("edge cases: fixture has %d, tlog re-derivation gives %d", len(edgeInFile), len(want))
		default:
			for i := range want {
				g, w := edgeInFile[i], want[i]
				if g.Name != w.Name || g.LeafHash != w.LeafHash || g.LeafIndex != w.LeafIndex || g.TreeSize != w.TreeSize ||
					strings.Join(g.Path, ",") != strings.Join(w.Path, ",") || g.Root != w.Root || g.Valid != w.Valid ||
					g.UpstreamExpectation != w.UpstreamExpectation {
					c.fail("edge case %d %q differs from its tlog re-derivation %q", i, g.Name, w.Name)
					continue
				}
				counts["edge"]++
				c.ok()
			}
		}
	}

	if strings.Join(discrepancies, "\n") != strings.Join(f.Discrepancies, "\n") {
		c.fail("discrepancies in the fixture do not match what tlog.CheckRecord and RFC 9162 give now")
	} else {
		c.ok()
	}
	var deviations []string
	for _, in := range f.Inclusion {
		if in.RFC9162Valid != nil {
			deviations = append(deviations, rfcDeviation(in))
		}
	}
	if strings.Join(deviations, "\n") != strings.Join(f.Deviations, "\n") {
		c.fail("deviations in the fixture do not match the cases that carry rfc9162_valid")
	}
	// Every entry is named "published: ...", "generated: ..." or "derived: ...".
	if f.EmptyRoot != nil {
		counts["published"]++
	}
	for _, t := range f.Trees {
		counts[entryKind(t.Name)]++
	}
	for _, h := range f.HashChecks {
		counts[entryKind(h.Name)]++
	}
	if counts["unnamed"] > 0 {
		c.fail("%d entries are not named published:, generated: or derived:", counts["unnamed"])
	}
	return c, counts
}

func entryKind(name string) string {
	for _, k := range []string{"published", "generated", "derived"} {
		if strings.HasPrefix(name, k+": ") {
			return k
		}
	}
	return "unnamed"
}

func equalProof(a, b tlog.RecordProof) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func linkedVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, d := range bi.Deps {
		if d.Path == modulePath {
			if d.Replace != nil {
				return d.Replace.Version
			}
			return d.Version
		}
	}
	return "unknown"
}

const moduleID = modulePath + "@" + moduleVersion

const usageText = `usage: go run . -fixtures <path> [-write] [-ours <path>]

  -fixtures <path>  the fixture file, vectors/interop/x-mod-sumdb-tlog.json (required)
  -write            regenerate the fixture from the upstream literals and tlog,
                    write it to the -fixtures path, then check it
  -ours <path>      also check the truestamp_merkle vectors/merkle.json with tlog

From interop/go/x-mod-sumdb-tlog/ in the truestamp_merkle repository:

  go run . -fixtures ../../../vectors/interop/x-mod-sumdb-tlog.json -ours ../../../vectors/merkle.json
  go run . -fixtures ../../../vectors/interop/x-mod-sumdb-tlog.json -write
`

// maxFailLines caps the FAIL lines one phase prints.
const maxFailLines = 50

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// failLine formats one FAIL line of a phase ("usage", "fixtures" or "ours").
// A message never spans lines: any line break in it is escaped.
func failLine(phase, msg string) string {
	msg = strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(msg)
	if phase == "usage" {
		return "FAIL usage: " + msg
	}
	return "FAIL " + phase + " " + moduleID + ": " + msg
}

// guard runs one phase and turns a panic in it into one failure.
func guard(phase func() (string, []string)) (okLine string, errs []string) {
	defer func() {
		if r := recover(); r != nil {
			okLine, errs = "", []string{fmt.Sprintf("internal error: %v", r)}
		}
	}()
	return phase()
}

// run parses the arguments, runs the phases, prints the result lines and
// returns the exit status.
func run(args []string, stdout, stderr io.Writer) (status int) {
	current := "usage"
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(stdout, failLine(current, fmt.Sprintf("internal error: %v", r)))
			status = 1
		}
	}()

	var opts options
	var help bool
	_, errs := guard(func() (string, []string) {
		var err error
		opts, help, err = parseArgs(args)
		if err != nil {
			return "", []string{err.Error()}
		}
		return "", nil
	})
	if len(errs) > 0 {
		fmt.Fprintln(stdout, failLine("usage", errs[0]))
		return 1
	}
	if help {
		fmt.Fprint(stderr, usageText)
		return 0
	}

	report := func(phase, okLine string, errs []string) {
		if len(errs) == 0 {
			fmt.Fprintln(stdout, okLine)
			return
		}
		status = 1
		for i, e := range errs {
			if i == maxFailLines {
				fmt.Fprintln(stdout, failLine(phase, fmt.Sprintf("%d more failures not shown", len(errs)-maxFailLines)))
				break
			}
			fmt.Fprintln(stdout, failLine(phase, e))
		}
	}

	current = "fixtures"
	okLine, errs := guard(func() (string, []string) { return checkFixture(opts.fixtures, opts.write) })
	report(current, okLine, errs)
	if opts.oursSet {
		current = "ours"
		okLine, errs := guard(func() (string, []string) { return checkOurs(opts.ours) })
		report(current, okLine, errs)
	}
	return status
}

type options struct {
	fixtures string
	ours     string
	oursSet  bool
	write    bool
}

// pathFlag is a flag that takes a path: given at most once, never empty, and
// never another flag, so "-ours -write" is a missing value, not a path.
type pathFlag struct {
	set bool
	val string
}

func (f *pathFlag) String() string {
	if f == nil {
		return ""
	}
	return f.val
}

func (f *pathFlag) Set(s string) error {
	switch {
	case f.set:
		return errors.New("the flag is given more than once")
	case s == "":
		return errors.New("the path is empty")
	case strings.HasPrefix(s, "-"):
		return errors.New("the path is missing (the next argument is a flag)")
	}
	f.set, f.val = true, s
	return nil
}

// onceBool is a boolean flag that may be given at most once.
type onceBool struct {
	set, val bool
}

func (b *onceBool) IsBoolFlag() bool { return true }

func (b *onceBool) String() string {
	if b == nil {
		return "false"
	}
	return strconv.FormatBool(b.val)
}

func (b *onceBool) Set(s string) error {
	if b.set {
		return errors.New("the flag is given more than once")
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return errors.New("not true or false")
	}
	b.set, b.val = true, v
	return nil
}

// parseArgs reads the command line. help is true for -h or -help; any other
// problem is an error, reported as one "FAIL usage:" line.
func parseArgs(args []string) (opts options, help bool, err error) {
	fs := flag.NewFlagSet("x-mod-sumdb-tlog", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	var fixtures, ours pathFlag
	var write onceBool
	fs.Var(&fixtures, "fixtures", "the fixture file (required)")
	fs.Var(&ours, "ours", "the truestamp_merkle vectors/merkle.json")
	fs.Var(&write, "write", "regenerate the fixture, then check it")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, true, nil
		}
		return opts, false, err
	}
	if fs.NArg() != 0 {
		return opts, false, fmt.Errorf("unexpected positional argument %q", fs.Arg(0))
	}
	if !fixtures.set {
		return opts, false, errors.New("-fixtures <path> is required")
	}
	return options{fixtures: fixtures.val, ours: ours.val, oursSet: ours.set, write: write.val}, false, nil
}

// checkFixture regenerates the fixture (and writes it when write is set),
// reads the file at path and checks it. It returns the OK line, or the
// failures.
func checkFixture(path string, write bool) (string, []string) {
	if v := linkedVersion(); v != moduleVersion {
		return "", []string{fmt.Sprintf("linked %s is %s, program expects %s", modulePath, v, moduleVersion)}
	}
	gen, err := generate()
	if err != nil {
		return "", []string{"generate: " + err.Error()}
	}
	genBytes, err := encode(gen)
	if err != nil {
		return "", []string{"encode: " + err.Error()}
	}
	if write {
		if err := os.WriteFile(path, genBytes, 0o644); err != nil {
			return "", []string{"write: " + err.Error()}
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", []string{"read: " + err.Error()}
	}
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return "", []string{fmt.Sprintf("parse %s: %v", path, err)}
	}

	c, counts := verify(&f)
	extra := extraChecks(c, &f)
	if !bytes.Equal(raw, genBytes) {
		c.fail("%s is not byte-identical to the regeneration from upstream literals", path)
	}
	if bytes.ContainsRune(raw, '\u2014') {
		c.fail("%s contains an em dash", path)
	}
	if len(c.errs) > 0 {
		return "", c.errs
	}
	return fmt.Sprintf("OK fixtures %s: empty_root 1, hash_checks %d, trees %d, inclusion %d (valid %d, invalid %d; published %d, generated %d, of which %d edge cases), entries %d published + %d generated + %d derived, discrepancies %d, deviations %d, sumdb client lookups replayed with %d tlog checks, settling %d client cases valid and %d invalid, %s; fixture byte-identical to regeneration",
		moduleID, counts["hash_checks"], counts["trees"], counts["inclusion_valid"]+counts["inclusion_invalid"], counts["inclusion_valid"], counts["inclusion_invalid"],
		counts["inclusion_published"], counts["inclusion_generated"], counts["edge"],
		counts["published"], counts["generated"], counts["derived"], len(f.Discrepancies), len(f.Deviations),
		counts["client_replay_checks"], counts["client_valid"], counts["client_invalid"], extra), nil
}
