// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains short literals from github.com/google/certificate-transparency-go@v1.0.16
// (Apache-2.0, Copyright 2016 Google Inc. All Rights Reserved.): the error texts
// of merkletree/merkle_verifier.go:86, 89, 99 and 114, matched below. License:
// LICENSE-certificate-transparency-go in this directory.

package main

// The -ours check: the truestamp_merkle library's own known answers
// (vectors/merkle.json, written by the library's vectors/generate.exs from
// RFC 9162 section 2.1) checked with this module's own code. An entry's leaf
// data is its digest's 32 raw bytes, and a tree's leaves are its entries sorted
// by key, byte-wise ascending.
//
// The module has a hasher (HashEmpty, HashLeaf, HashChildren) and a verifier
// (VerifyInclusionProof, VerifyInclusionProofByHash, RootFromInclusionProof,
// RootFromInclusionProofAndHash), but no tree builder and no prover:
// MerkleTreeInterface and FullMerkleTreeInterface are declared and never
// implemented. So a tree's root is built by the RFC 9162 MTH recursion in
// main.go, which hashes only through the module's HashLeaf and HashChildren;
// the empty tree's root is the module's HashEmpty(); every leaf of every tree
// must pass the module's verifier against that root; and a tree's depth must
// be its longest RFC 9162 PATH over the module's hasher. A published path
// cannot be compared with a prover's output: it must pass the module's
// verifier, give the root through RootFromInclusionProof, and equal RFC 9162
// PATH over the module's hasher.
//
// Checked: constants.empty_root, trees (with depth), walk_accepts, and the
// walk_refusals whose error is index_out_of_range or wrong_path_length. The
// module has no counterpart for keys, a step cap, digest or node text rules,
// or a binary proof form, so entry_refusals, binary_refusals, max_steps,
// binary_hex and the other walk_refusals are not checked here.
//
// Strictness: constants, trees, walk_accepts and walk_refusals must be present
// and non-empty, and every tree with entries must list paths. Unknown fields
// are ignored. In a case this program checks, a required field that is missing
// or has the wrong type is a FAIL. The only skips are a checked refusal whose
// digest or a path node is text that is not a hex digest (no byte value
// exists for the module to take) and an integer outside int64 (the module's
// index and size type). Each skip is named on the OK line, and the number of
// skips is pinned below, so a new or vanished skip is a FAIL.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/certificate-transparency-go/merkletree"
)

// Pinned counts for the library's vectors/merkle.json. The module accepts no
// in-scope refusal. Four walk_accepts cases have a tree_size that does not fit
// int64 ("64 steps under the default cap", "the last of 2^63 + 1 entries",
// "index 2^64 - 2 of 2^64 - 1 entries" and "index 2^63 - 1 of 2^64 - 1
// entries"), and one in-scope walk_refusals case ("the path length is checked
// before any node") has the path node "bad".
const (
	oursLaxAccepted     = 0
	oursSkippedAccepts  = 4
	oursSkippedRefusals = 1
)

// jsonInt holds a JSON integer literal as written, so that values outside
// int64 (the module's index and size type) are recognized and skipped instead
// of failing the decode, while a string or a fraction still fails it.
type jsonInt struct{ raw string }

var intLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func (j *jsonInt) UnmarshalJSON(b []byte) error {
	if !intLiteral.Match(b) {
		return fmt.Errorf("not a JSON integer: %.40s", b)
	}
	j.raw = string(b)
	return nil
}

// int64 returns the value, and false when it does not fit an int64.
func (j *jsonInt) int64() (int64, bool) {
	v, err := strconv.ParseInt(j.raw, 10, 64)
	return v, err == nil
}

// A field of type json.RawMessage is nil when the member is absent and holds
// "null" when it is null; both count as missing.
func present(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

func startsWith(raw json.RawMessage, c byte) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && t[0] == c
}

// jsonString decodes a member that must be a JSON string.
func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if !startsWith(raw, '"') || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// jsonStringList decodes a member that must be a JSON list of strings.
func jsonStringList(raw json.RawMessage) ([]string, bool) {
	var items []json.RawMessage
	if !startsWith(raw, '[') || json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := jsonString(it)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// jsonInteger decodes a member that must be a JSON integer literal.
func jsonInteger(raw json.RawMessage) (*jsonInt, bool) {
	var j jsonInt
	if !present(raw) || json.Unmarshal(raw, &j) != nil {
		return nil, false
	}
	return &j, true
}

// jsonList decodes a member that must be a JSON list.
func jsonList(raw json.RawMessage) ([]json.RawMessage, bool) {
	var items []json.RawMessage
	if !startsWith(raw, '[') || json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	return items, true
}

type oursConstants struct {
	EmptyRoot json.RawMessage `json:"empty_root"`
}

type oursEntry struct {
	Key    json.RawMessage `json:"key"`
	Digest json.RawMessage `json:"digest"`
}

type oursTree struct {
	Name     json.RawMessage `json:"name"`
	Entries  json.RawMessage `json:"entries"`
	Root     json.RawMessage `json:"root"`
	Depth    json.RawMessage `json:"depth"`
	TreeSize json.RawMessage `json:"tree_size"`
	Paths    json.RawMessage `json:"paths"`
}

type oursTreePath struct {
	Key       json.RawMessage `json:"key"`
	Digest    json.RawMessage `json:"digest"`
	LeafIndex json.RawMessage `json:"leaf_index"`
	TreeSize  json.RawMessage `json:"tree_size"`
	Path      json.RawMessage `json:"path"`
}

type oursProof struct {
	LeafIndex json.RawMessage `json:"leaf_index"`
	TreeSize  json.RawMessage `json:"tree_size"`
	Path      json.RawMessage `json:"path"`
}

type oursWalkAccept struct {
	Name     json.RawMessage `json:"name"`
	Digest   json.RawMessage `json:"digest"`
	Proof    json.RawMessage `json:"proof"`
	MaxSteps json.RawMessage `json:"max_steps"`
	Root     json.RawMessage `json:"root"`
}

type oursRefusal struct {
	Name     json.RawMessage `json:"name"`
	Digest   json.RawMessage `json:"digest"`
	Proof    json.RawMessage `json:"proof"`
	MaxSteps json.RawMessage `json:"max_steps"`
	Error    json.RawMessage `json:"error"`
}

// decodeObject decodes raw, which must be a JSON object, into v.
func decodeObject(raw json.RawMessage, v interface{}) error {
	if !startsWith(raw, '{') {
		return errors.New("not a JSON object")
	}
	return json.Unmarshal(raw, v)
}

var hex32 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// digest32 decodes a 64-character lowercase hex digest.
func digest32(s string) ([]byte, bool) {
	if !hex32.MatchString(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

func digestList(ss []string) ([][]byte, bool) {
	out := make([][]byte, 0, len(ss))
	for _, s := range ss {
		b, ok := digest32(s)
		if !ok {
			return nil, false
		}
		out = append(out, b)
	}
	return out, true
}

// caseName names a case by its name member when that is a string.
func caseName(raw json.RawMessage, section string, i int) string {
	var probe struct {
		Name json.RawMessage `json:"name"`
	}
	if startsWith(raw, '{') && json.Unmarshal(raw, &probe) == nil {
		if s, ok := jsonString(probe.Name); ok {
			return fmt.Sprintf("%s %q", section, s)
		}
	}
	return fmt.Sprintf("%s[%d]", section, i)
}

// The module's refusal texts (merkletree/merkle_verifier.go at v1.0.16):
//
//	86:  fmt.Errorf("leafIndex %d > treeSize %d", leafIndex, treeSize)
//	89:  errors.New("leafIndex < 0 or treeSize < 1")
//	99:  fmt.Errorf("insuficient number of proof components (%d) for treeSize %d", len(proof), treeSize)
//	114: fmt.Errorf("invalid proof, expected %d components, but have %d", proofIndex, len(proof))
var (
	moduleIndexErr  = regexp.MustCompile(`^(leafIndex -?\d+ > treeSize -?\d+|leafIndex < 0 or treeSize < 1)$`)
	moduleLengthErr = regexp.MustCompile(`^(insuficient number of proof components \(\d+\) for treeSize -?\d+|invalid proof, expected \d+ components, but have \d+)$`)
)

// modErr formats a module error on one line, with a root mismatch in hex.
func modErr(err error) string {
	var rm merkletree.RootMismatchError
	if errors.As(err, &rm) {
		return fmt.Sprintf("calculated root %s, expected %s", hx(rm.CalculatedRoot), hx(rm.ExpectedRoot))
	}
	return oneLine(err.Error())
}

// refusalKind names the library error a module refusal corresponds to.
func refusalKind(err error) string {
	switch {
	case moduleIndexErr.MatchString(err.Error()):
		return "index_out_of_range"
	case moduleLengthErr.MatchString(err.Error()):
		return "wrong_path_length"
	}
	return "other: " + err.Error()
}

// uncheckedBits folds every path node into the leaf hash, taking the side
// from the leaf index's bits, with no index or length check.
func uncheckedBits(leafIndex int64, leafHash []byte, path [][]byte) []byte {
	r := leafHash
	for i, p := range path {
		if (leafIndex>>uint(i))&1 == 1 {
			r = hasher.HashChildren(p, r)
		} else {
			r = hasher.HashChildren(r, p)
		}
	}
	return r
}

// uncheckedRFC is the RFC 9162 section 2.1.3.2 loop with its index, size and
// length checks removed: the root the path reaches if nothing is refused.
func uncheckedRFC(leafIndex, treeSize int64, leafHash []byte, path [][]byte) []byte {
	fn, sn := leafIndex, treeSize-1
	r := leafHash
	for _, p := range path {
		if fn&1 == 1 || fn == sn {
			r = hasher.HashChildren(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = hasher.HashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return r
}

type oursStats struct {
	trees, emptyTrees, leaves, paths   int
	accepts, acceptsSkipped            int
	refusals, refused, refusalsSkipped int
	refusedByKind                      map[string]int
	refusalsOther, laxAccepted         int
	walkAccepts, walkRefusals          int
	skippedNames                       []string
}

type badFunc func(format string, a ...interface{})

// checkOurs checks the library's vectors file at path with the module. It
// returns the counts for the OK line, or the problems.
func checkOurs(path string) (string, []string) {
	var errs []string
	bad := func(format string, a ...interface{}) { errs = append(errs, fmt.Sprintf(format, a...)) }

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", []string{fmt.Sprintf("read %s: %v", path, err)}
	}
	var doc map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if !startsWith(raw, '{') {
		return "", []string{fmt.Sprintf("parse %s: the top level is not a JSON object", path)}
	}
	if err := dec.Decode(&doc); err != nil {
		return "", []string{fmt.Sprintf("parse %s: %v", path, err)}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", []string{fmt.Sprintf("parse %s: data after the top-level object", path)}
	}

	// The four checked sections must be present and non-empty.
	var constants oursConstants
	if c := doc["constants"]; !present(c) || decodeObject(c, &constants) != nil {
		bad("constants is missing, null or not an object")
	}
	sections := map[string][]json.RawMessage{}
	for _, name := range []string{"trees", "walk_accepts", "walk_refusals"} {
		items, ok := jsonList(doc[name])
		switch {
		case !present(doc[name]):
			bad("%s is missing or null", name)
		case !ok:
			bad("%s is not a list", name)
		case len(items) == 0:
			bad("%s is empty", name)
		}
		sections[name] = items
	}
	if len(errs) > 0 {
		return "", errs
	}

	st := &oursStats{refusedByKind: map[string]int{}}

	// constants.empty_root: the module's HashEmpty().
	emptyRoot := hasher.HashEmpty()
	if s, ok := jsonString(constants.EmptyRoot); !ok {
		bad("constants.empty_root is missing or not a string")
	} else if er, ok := digest32(s); !ok || !bytes.Equal(er, emptyRoot) {
		bad("constants.empty_root %q is not the module's HashEmpty() %s", s, hx(emptyRoot))
	}

	for i, t := range sections["trees"] {
		checkOursTree(t, i, emptyRoot, st, bad)
	}
	for i, w := range sections["walk_accepts"] {
		st.walkAccepts++
		checkOursAccept(w, i, st, bad)
	}
	for i, r := range sections["walk_refusals"] {
		st.walkRefusals++
		checkOursRefusal(r, i, st, bad)
	}
	if st.laxAccepted != oursLaxAccepted {
		bad("the module accepted %d in-scope walk_refusals, expected %d", st.laxAccepted, oursLaxAccepted)
	}
	if st.acceptsSkipped != oursSkippedAccepts {
		bad("%d walk_accepts skipped, expected %d", st.acceptsSkipped, oursSkippedAccepts)
	}
	if st.refusalsSkipped != oursSkippedRefusals {
		bad("%d in-scope walk_refusals skipped, expected %d", st.refusalsSkipped, oursSkippedRefusals)
	}
	if len(errs) > 0 {
		return "", errs
	}

	return fmt.Sprintf("trees %d (roots by RFC 9162 MTH over the module's hasher %d, empty tree = HashEmpty() %d, depth = longest RFC 9162 PATH over the module's hasher %d, leaves accepted by the module's verifier %d), paths %d (module verifier, RootFromInclusionProof and RFC 9162 PATH agree on all; the module has no prover), walk_accepts %d: %d accepted, %d skipped, walk_refusals %d: %d in scope, %d refused (index_out_of_range %d, wrong_path_length %d), %d skipped, %d other errors not checked, lax acceptances %d, skipped %d (%s)",
		st.trees, st.trees, st.emptyTrees, st.trees, st.leaves, st.paths,
		st.walkAccepts, st.accepts, st.acceptsSkipped,
		st.walkRefusals, st.refusals, st.refused, st.refusedByKind["index_out_of_range"], st.refusedByKind["wrong_path_length"],
		st.refusalsSkipped, st.refusalsOther, st.laxAccepted,
		len(st.skippedNames), strings.Join(st.skippedNames, "; ")), nil
}

func checkOursTree(raw json.RawMessage, i int, emptyRoot []byte, st *oursStats, bad badFunc) {
	name := caseName(raw, "tree", i)
	var t oursTree
	if err := decodeObject(raw, &t); err != nil {
		bad("%s: %v", name, err)
		return
	}
	_, nameOK := jsonString(t.Name)
	rootText, rootOK := jsonString(t.Root)
	entries, entriesOK := jsonList(t.Entries)
	paths, pathsOK := jsonList(t.Paths)
	size, sizeOK := jsonInteger(t.TreeSize)
	depth, depthOK := jsonInteger(t.Depth)
	if !nameOK || !rootOK || !entriesOK || !pathsOK || !sizeOK || !depthOK {
		bad("%s: needs a string name and root, integer depth and tree_size, and lists entries and paths", name)
		return
	}
	root, ok := digest32(rootText)
	if !ok {
		bad("%s: root is not a 64-character lowercase hex digest", name)
		return
	}
	n, ok := size.int64()
	if !ok || n != int64(len(entries)) {
		bad("%s: tree_size %s does not equal its %d entries", name, size.raw, len(entries))
		return
	}
	if len(entries) > 0 && len(paths) == 0 {
		bad("%s: a tree with entries must list paths", name)
	}

	type leaf struct {
		key    string
		digest []byte
	}
	leaves := make([]leaf, 0, len(entries))
	for j, eraw := range entries {
		var e oursEntry
		if err := decodeObject(eraw, &e); err != nil {
			bad("%s: entry %d: %v", name, j, err)
			return
		}
		key, kok := jsonString(e.Key)
		dtext, dok := jsonString(e.Digest)
		d, hok := digest32(dtext)
		if !kok || !dok || !hok {
			bad("%s: entry %d needs a string key and a 64-character lowercase hex digest", name, j)
			return
		}
		leaves = append(leaves, leaf{key, d})
	}
	// Byte-wise ascending by key: Go compares strings byte by byte.
	sort.SliceStable(leaves, func(a, b int) bool { return leaves[a].key < leaves[b].key })
	pos := map[string]int{}
	lh := make([][]byte, len(leaves))
	for m, l := range leaves {
		if _, dup := pos[l.key]; dup {
			bad("%s: key %q appears twice", name, l.key)
			return
		}
		pos[l.key] = m
		lh[m] = hasher.HashLeaf(l.digest)
	}

	// (a) the root.
	st.trees++
	if got := rfcMTH(lh); !bytes.Equal(got, root) {
		bad("%s: root %s, but RFC 9162 MTH over the module's hasher gives %s", name, rootText, hx(got))
	}
	if len(lh) == 0 {
		st.emptyTrees++
		if !bytes.Equal(root, emptyRoot) {
			bad("%s: the empty tree's root is not the module's HashEmpty()", name)
		}
	}
	// The module's verifier must accept every leaf against the root, and the
	// depth is the longest RFC 9162 PATH over the module's hasher.
	rejected, firstErr, longest := 0, "", 0
	for m := range lh {
		p := rfcPath(lh, m)
		if len(p) > longest {
			longest = len(p)
		}
		if err := realVerifier.VerifyInclusionProofByHash(int64(m), n, p, root, lh[m]); err != nil {
			if rejected == 0 {
				firstErr = fmt.Sprintf("leaf %d (key %q): %s", m, leaves[m].key, modErr(err))
			}
			rejected++
		}
		st.leaves++
	}
	if rejected > 0 {
		bad("%s: the module's verifier rejects %d of %d leaves against the root, first %s", name, rejected, len(lh), firstErr)
	}
	if d, ok := depth.int64(); !ok || d != int64(longest) {
		bad("%s: depth %s, but the longest RFC 9162 PATH over the module's hasher has %d nodes", name, depth.raw, longest)
	}

	// (b) every published path.
	for j, praw := range paths {
		pname := fmt.Sprintf("%s path %d", name, j)
		var p oursTreePath
		if err := decodeObject(praw, &p); err != nil {
			bad("%s: %v", pname, err)
			continue
		}
		key, kok := jsonString(p.Key)
		if kok {
			pname = fmt.Sprintf("%s path for key %q", name, key)
		}
		dtext, dok := jsonString(p.Digest)
		d, hok := digest32(dtext)
		nodeTexts, lok := jsonStringList(p.Path)
		nodes, nok := digestList(nodeTexts)
		idxJ, iok := jsonInteger(p.LeafIndex)
		psizeJ, sok := jsonInteger(p.TreeSize)
		if !kok || !dok || !hok || !lok || !nok || !iok || !sok {
			bad("%s: needs a string key, a hex digest, integer leaf_index and tree_size, and a path of hex digests", pname)
			continue
		}
		st.paths++
		m, inTree := pos[key]
		idx, iok := idxJ.int64()
		psize, sok := psizeJ.int64()
		switch {
		case !inTree:
			bad("%s: the key is not in the tree", pname)
			continue
		case !iok || idx != int64(m):
			bad("%s: leaf_index %s, but the key sorts to position %d", pname, idxJ.raw, m)
			continue
		case !sok || psize != n:
			bad("%s: tree_size %s, but the tree has %d entries", pname, psizeJ.raw, n)
			continue
		case !bytes.Equal(d, leaves[m].digest):
			bad("%s: digest differs from the tree entry's", pname)
			continue
		}
		if err := realVerifier.VerifyInclusionProof(idx, n, nodes, root, d); err != nil {
			bad("%s: the module's VerifyInclusionProof rejects it: %s", pname, modErr(err))
		}
		if err := realVerifier.VerifyInclusionProofByHash(idx, n, nodes, root, lh[m]); err != nil {
			bad("%s: the module's VerifyInclusionProofByHash rejects it: %s", pname, modErr(err))
		}
		if got, err := realVerifier.RootFromInclusionProof(idx, n, nodes, d); err != nil || !bytes.Equal(got, root) {
			bad("%s: the module's RootFromInclusionProof does not give the root (%v)", pname, err)
		}
		if !equalProofs(rfcPath(lh, m), nodes) {
			bad("%s: path differs from RFC 9162 PATH over the module's hasher", pname)
		}
	}
}

func checkOursAccept(raw json.RawMessage, i int, st *oursStats, bad badFunc) {
	name := caseName(raw, "walk_accepts", i)
	var w oursWalkAccept
	if err := decodeObject(raw, &w); err != nil {
		bad("%s: %v", name, err)
		return
	}
	var p oursProof
	perr := decodeObject(w.Proof, &p)
	_, nameOK := jsonString(w.Name)
	dtext, dok := jsonString(w.Digest)
	d, dhex := digest32(dtext)
	rtext, rok := jsonString(w.Root)
	root, rhex := digest32(rtext)
	_, mok := jsonInteger(w.MaxSteps)
	idxJ, iok := jsonInteger(p.LeafIndex)
	sizeJ, sok := jsonInteger(p.TreeSize)
	nodeTexts, lok := jsonStringList(p.Path)
	nodes, nok := digestList(nodeTexts)
	if !nameOK || !dok || !dhex || !rok || !rhex || !mok || perr != nil || !iok || !sok || !lok || !nok {
		bad("%s: needs a string name, a hex digest, a hex root, integer max_steps, and a proof object with integer leaf_index and tree_size and a path of hex digests", name)
		return
	}
	idx, iok := idxJ.int64()
	size, sok := sizeJ.int64()
	if !iok || !sok {
		st.acceptsSkipped++
		st.skippedNames = append(st.skippedNames, fmt.Sprintf("%s: leaf_index %s, tree_size %s outside int64", name, idxJ.raw, sizeJ.raw))
		return
	}
	// (c) the module must accept it; the module has no step cap, so max_steps
	// has no counterpart.
	lhash := hasher.HashLeaf(d)
	ok := true
	if err := realVerifier.VerifyInclusionProof(idx, size, nodes, root, d); err != nil {
		bad("%s: the module's VerifyInclusionProof rejects it: %s", name, modErr(err))
		ok = false
	}
	if err := realVerifier.VerifyInclusionProofByHash(idx, size, nodes, root, lhash); err != nil {
		bad("%s: the module's VerifyInclusionProofByHash rejects it: %s", name, modErr(err))
		ok = false
	}
	if got, err := realVerifier.RootFromInclusionProofAndHash(idx, size, nodes, lhash); err != nil || !bytes.Equal(got, root) {
		bad("%s: the module's RootFromInclusionProofAndHash does not give the root (%v)", name, err)
		ok = false
	}
	if !rfcVerify(idx, size, lhash, nodes, root) {
		bad("%s: RFC 9162 section 2.1.3.2 over the module's hasher rejects it", name)
		ok = false
	}
	if ok {
		st.accepts++
	}
}

func checkOursRefusal(raw json.RawMessage, i int, st *oursStats, bad badFunc) {
	name := caseName(raw, "walk_refusals", i)
	var r oursRefusal
	if err := decodeObject(raw, &r); err != nil {
		bad("%s: %v", name, err)
		return
	}
	_, nameOK := jsonString(r.Name)
	kind, errOK := jsonString(r.Error)
	if !nameOK || !errOK {
		bad("%s: needs a string name and a string error", name)
		return
	}
	if kind != "index_out_of_range" && kind != "wrong_path_length" {
		st.refusalsOther++
		return
	}
	st.refusals++

	// An in-scope case: every member it needs must be there with its type.
	var p oursProof
	perr := decodeObject(r.Proof, &p)
	dtext, dok := jsonString(r.Digest)
	_, mok := jsonInteger(r.MaxSteps)
	idxJ, iok := jsonInteger(p.LeafIndex)
	sizeJ, sok := jsonInteger(p.TreeSize)
	nodeTexts, lok := jsonStringList(p.Path)
	if !dok || !mok || perr != nil || !iok || !sok || !lok {
		bad("%s: needs a string digest, integer max_steps, and a proof object with integer leaf_index and tree_size and a list of strings as path", name)
		return
	}
	skip := func(why string) {
		st.refusalsSkipped++
		st.skippedNames = append(st.skippedNames, fmt.Sprintf("%s: %s", name, why))
	}
	d, dhex := digest32(dtext)
	nodes, nhex := digestList(nodeTexts)
	idx, i64 := idxJ.int64()
	size, s64 := sizeJ.int64()
	switch {
	case !dhex:
		skip(fmt.Sprintf("digest %.70q is not a hex digest", dtext))
		return
	case !nhex:
		skip("a path node is not a hex digest")
		return
	case !i64 || !s64:
		skip(fmt.Sprintf("leaf_index %s, tree_size %s outside int64", idxJ.raw, sizeJ.raw))
		return
	}

	// (d) the module must refuse, for the same reason, whatever the root: the
	// candidates are the roots the path reaches under two unchecked chains,
	// plus any root the module itself computes.
	lhash := hasher.HashLeaf(d)
	candidates := [][]byte{uncheckedBits(idx, lhash, nodes), uncheckedRFC(idx, size, lhash, nodes)}
	refusedOK := true
	if got, err := realVerifier.RootFromInclusionProofAndHash(idx, size, nodes, lhash); err == nil {
		bad("%s: the module's RootFromInclusionProofAndHash computes a root instead of refusing (%s expected)", name, kind)
		candidates = append(candidates, got)
		refusedOK = false
	} else if got := refusalKind(err); got != kind {
		bad("%s: the module refuses with %q, which is not %s", name, err.Error(), kind)
		refusedOK = false
	}
	accepted := false
	for _, root := range candidates {
		if realVerifier.VerifyInclusionProofByHash(idx, size, nodes, root, lhash) == nil ||
			realVerifier.VerifyInclusionProof(idx, size, nodes, root, d) == nil {
			accepted = true
		}
	}
	if accepted {
		st.laxAccepted++
		bad("%s: the module's verifier accepts a proof it must refuse (%s)", name, kind)
		refusedOK = false
	}
	if refusedOK {
		st.refused++
		st.refusedByKind[kind]++
	}
}
