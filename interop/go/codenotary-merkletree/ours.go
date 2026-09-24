// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains material from github.com/codenotary/merkletree@v0.1.2: the
// comments below quote a short code fragment of tree.go (line 214) and cite
// tree.go by line, Copyright 2019-2020 vChain, Inc., licensed under the
// Apache License, Version 2.0 (LICENSE-codenotary-merkletree; see NOTICE).

package main

// -ours: truestamp_merkle's own known answers (vectors/merkle.json, written
// by vectors/generate.exs) checked with github.com/codenotary/merkletree's
// own functions.
//
// The leaf data of an entry is the 32 raw bytes of its digest, and a tree's
// leaves are its entries in byte-wise ascending key order. With the module:
//
//   - every tree root equals merkletree.MTH over those leaves and the Root of
//     an incremental store built with merkletree.Append, the empty tree
//     included (both give SHA-256("") for no leaves);
//   - every depth equals the longest path merkletree.InclusionProof gives for
//     any leaf of the store (0 for the empty tree, which has no leaves), and
//     merkletree.Depth of the store for every non-empty tree (Depth is -1 for
//     an empty store);
//   - every path equals merkletree.MPath and merkletree.InclusionProof, and
//     merkletree.Path.VerifyInclusion(tree_size - 1, leaf_index, root,
//     merkletree.LeafHash(digest)) accepts it;
//   - every walk_accepts case is accepted the same way;
//   - every walk_refusals case whose error is index_out_of_range or
//     wrong_path_length is offered the root an unchecked chain reaches
//     (refChainUnchecked in reference.go), and the module must refuse it.
//     The module does not check path length, so it accepts some
//     wrong_path_length cases; their number must equal
//     laxAcceptedWrongLength.
//
// The file must hold constants, trees, walk_accepts and walk_refusals, each
// present and non-empty, and every tree with entries must list paths. Fields
// this program does not know are ignored. A field it reads that is missing or
// has the wrong JSON type is a FAIL. Only two things are skipped, and each
// skip is counted and named on the OK line: a digest or path node that is not
// hex (no byte value exists), and an integer the module's API cannot hold
// (leaf_index and at = tree_size - 1 are uint64 values, so a negative number,
// a number above 2^64 - 1, or a tree_size of 0 in a refusal).
//
// The RFC 9162 reference in reference.go gives a second answer for every
// root, path and verdict, and binary_hex is checked against the JSON fields
// it encodes. entry_refusals, binary_refusals, max_steps and the other
// walk_refusals errors test layers the module does not have (keys, the
// binary proof form, a step cap, text parsing) and are only counted.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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

	cn "github.com/codenotary/merkletree"
)

// laxAcceptedWrongLength is the number of walk_refusals cases with error
// wrong_path_length that merkletree.Path.VerifyInclusion accepts when offered
// the root an unchecked chain reaches. tree.go:192-215 ends on
// `at == i && h == root` and never compares the path length with the tree
// size, so once i == at every further node is hashed in from the left
// (discrepancies[1] of the fixture). In the vectors this admits "one node
// extra" (leaf 0 of 3 with 3 nodes) and "a node for one entry" (leaf 0 of 1
// with 1 node). A change in the module or in the vectors changes the count.
const laxAcceptedWrongLength = 2

// ---------------------------------------------------------------------------
// JSON fields
// ---------------------------------------------------------------------------

type jsonObject map[string]json.RawMessage

// firstByte is the first non-space byte of a JSON value, or 0 when the value
// is missing.
func firstByte(raw json.RawMessage) byte {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 {
		return 0
	}
	return t[0]
}

func asObject(raw json.RawMessage) (jsonObject, bool) {
	if firstByte(raw) != '{' {
		return nil, false
	}
	var o jsonObject
	if json.Unmarshal(raw, &o) != nil {
		return nil, false
	}
	return o, true
}

func asList(raw json.RawMessage) ([]json.RawMessage, bool) {
	if firstByte(raw) != '[' {
		return nil, false
	}
	var l []json.RawMessage
	if json.Unmarshal(raw, &l) != nil {
		return nil, false
	}
	return l, true
}

func asString(raw json.RawMessage) (string, bool) {
	if firstByte(raw) != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// asStrings reads a JSON list of strings.
func asStrings(raw json.RawMessage) ([]string, bool) {
	l, ok := asList(raw)
	if !ok {
		return nil, false
	}
	out := make([]string, len(l))
	for i, e := range l {
		s, ok := asString(e)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

type intClass int

const (
	intU64      intClass = iota // a JSON integer in 0..2^64-1
	intNegative                 // a JSON integer below 0
	intTooBig                   // a JSON integer above 2^64-1
	intNot                      // missing, null, or not a JSON integer
)

var jsonIntRe = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func classifyUint(raw json.RawMessage) (uint64, intClass) {
	s := string(bytes.TrimSpace(raw))
	if !jsonIntRe.MatchString(s) {
		return 0, intNot
	}
	if strings.HasPrefix(s, "-") {
		return 0, intNegative
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, intTooBig
	}
	return v, intU64
}

// missing names the fields of o that are absent or null.
func missing(o jsonObject, names ...string) []string {
	var out []string
	for _, n := range names {
		if v, ok := o[n]; !ok || string(bytes.TrimSpace(v)) == "null" {
			out = append(out, n)
		}
	}
	return out
}

// binaryForm is the library's binary proof form: leaf_index and tree_size as
// unsigned 64-bit big-endian integers, then the path nodes.
func binaryForm(index, size uint64, path [][sha256.Size]byte) string {
	b := make([]byte, 16, 16+32*len(path))
	binary.BigEndian.PutUint64(b[0:8], index)
	binary.BigEndian.PutUint64(b[8:16], size)
	for _, p := range path {
		b = append(b, p[:]...)
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

type oursCounts struct {
	trees, emptyTrees, depthByDepth, paths   int
	accepts                                  int
	acceptSkips                              []string
	refusedIndex, refusedLength, laxAccepted int
	refusalSkips                             []string
	outOfScope                               map[string]int
	laxNames                                 []string
	entryRefusals, binaryRefusals            int
}

type failer func(format string, a ...interface{})

func checkOurs(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		failf("ours", "%s: %v", path, err)
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var top json.RawMessage
	if err := dec.Decode(&top); err != nil {
		failf("ours", "%s: %v", path, err)
		return false
	}
	if err := dec.Decode(&json.RawMessage{}); !errors.Is(err, io.EOF) {
		failf("ours", "%s: trailing data after the JSON object", path)
		return false
	}
	of, ok := asObject(top)
	if !ok {
		failf("ours", "%s: the top level is not a JSON object", path)
		return false
	}
	nfail := 0
	cc := evaluateOurs(of, func(format string, a ...interface{}) {
		nfail++
		failf("ours", format, a...)
	})
	if nfail > 0 {
		return false
	}
	var scope []string
	for _, k := range sortedKeys(cc.outOfScope) {
		scope = append(scope, fmt.Sprintf("%s %d", k, cc.outOfScope[k]))
	}
	fmt.Printf("OK ours %s@%s: trees %d (roots equal merkletree.MTH and Append/Root over the digests in key order, %d empty; depth equals the longest merkletree.InclusionProof path for all %d and merkletree.Depth for the %d non-empty), "+
		"paths %d (each equals merkletree.MPath and InclusionProof and VerifyInclusion accepts it), "+
		"walk_accepts %d accepted, %s, "+
		"walk_refusals index_out_of_range %d refused, wrong_path_length %d refused and %d accepted by the module's lax length check as pinned (%s), %s, out of scope %s; "+
		"not applicable: entry_refusals %d, binary_refusals %d; RFC 9162 reference and binary_hex agree throughout\n",
		modulePath, moduleVersion,
		cc.trees, cc.emptyTrees, cc.trees, cc.depthByDepth, cc.paths,
		cc.accepts, skipText(cc.acceptSkips),
		cc.refusedIndex, cc.refusedLength, cc.laxAccepted, strings.Join(cc.laxNames, ", "), skipText(cc.refusalSkips),
		strings.Join(scope, ", "), cc.entryRefusals, cc.binaryRefusals)
	return true
}

// skipText is "0 skipped" or "N skipped (<name>: <reason>; ...)".
func skipText(skips []string) string {
	if len(skips) == 0 {
		return "0 skipped"
	}
	return fmt.Sprintf("%d skipped (%s)", len(skips), strings.Join(skips, "; "))
}

func sortedKeys(m map[string]int) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// requireList reads a required top-level section that must be a non-empty
// list.
func requireList(of jsonObject, name string, bad failer) ([]json.RawMessage, bool) {
	raw, present := of[name]
	if !present {
		bad("%s is missing", name)
		return nil, false
	}
	l, ok := asList(raw)
	if !ok {
		bad("%s is not a list", name)
		return nil, false
	}
	if len(l) == 0 {
		bad("%s is empty", name)
		return nil, false
	}
	return l, true
}

// optionalCount counts a section this program does not check; when present
// it must be a list.
func optionalCount(of jsonObject, name string, bad failer) int {
	raw, present := of[name]
	if !present {
		return 0
	}
	l, ok := asList(raw)
	if !ok {
		bad("%s is not a list", name)
		return 0
	}
	return len(l)
}

func evaluateOurs(of jsonObject, bad failer) oursCounts {
	cc := oursCounts{outOfScope: map[string]int{}}

	if _, ok := asString(of["description"]); !ok {
		bad("description is missing or not a string")
	}
	evaluateConstants(of, bad)
	cc.entryRefusals = optionalCount(of, "entry_refusals", bad)
	cc.binaryRefusals = optionalCount(of, "binary_refusals", bad)

	if trees, ok := requireList(of, "trees", bad); ok {
		for ti, raw := range trees {
			evaluateOursTree(raw, ti, &cc, bad)
		}
	}
	if accepts, ok := requireList(of, "walk_accepts", bad); ok {
		for ai, raw := range accepts {
			evaluateOursAccept(raw, ai, &cc, bad)
		}
	}
	if refusals, ok := requireList(of, "walk_refusals", bad); ok {
		for ri, raw := range refusals {
			evaluateOursRefusal(raw, ri, &cc, bad)
		}
		if cc.laxAccepted != laxAcceptedWrongLength {
			bad("walk_refusals: the module accepts %d wrong_path_length cases [%s], expected laxAcceptedWrongLength = %d",
				cc.laxAccepted, strings.Join(cc.laxNames, ", "), laxAcceptedWrongLength)
		}
	}
	return cc
}

func evaluateConstants(of jsonObject, bad failer) {
	raw, present := of["constants"]
	if !present {
		bad("constants is missing")
		return
	}
	c, ok := asObject(raw)
	if !ok {
		bad("constants is not an object")
		return
	}
	if len(c) == 0 {
		bad("constants is empty")
		return
	}
	if s, ok := asString(c["empty_root"]); !ok {
		bad("constants.empty_root is missing or not a string")
	} else if e, err := dec32(s); err != nil {
		bad("constants.empty_root: %v", err)
	} else if e != cn.MTH(nil) || e != cn.Root(cn.NewMemStore()) {
		bad("constants.empty_root %s is not merkletree.MTH(nil) / Root(empty store) %s", s, hx32(cn.MTH(nil)))
	}
	if _, k := classifyUint(c["max_steps"]); k == intNot {
		bad("constants.max_steps is missing or not an integer")
	}
	if _, k := classifyUint(c["max_tree_size"]); k == intNot {
		bad("constants.max_tree_size is missing or not an integer")
	}
}

// nameOf labels a case by its name when it has one, else by its position.
func nameOf(o jsonObject, section string, i int) string {
	if s, ok := asString(o["name"]); ok {
		return fmt.Sprintf("%s %q", section, s)
	}
	return fmt.Sprintf("%s[%d]", section, i)
}

// decNodes reads a list of 32-byte hashes, each 64 lowercase hex characters.
func decNodes(texts []string) ([][sha256.Size]byte, error) {
	out := make([][sha256.Size]byte, len(texts))
	for i, s := range texts {
		h, err := dec32(s)
		if err != nil {
			return nil, fmt.Errorf("node %d: %v", i, err)
		}
		out[i] = h
	}
	return out, nil
}

func evaluateOursTree(raw json.RawMessage, ti int, cc *oursCounts, bad failer) {
	cc.trees++
	t, ok := asObject(raw)
	if !ok {
		bad("trees[%d] is not an object", ti)
		return
	}
	label := nameOf(t, "tree", ti)
	if m := missing(t, "name", "entries", "root", "depth", "tree_size", "paths"); len(m) > 0 {
		bad("%s: missing %s", label, strings.Join(m, ", "))
		return
	}
	if _, ok := asString(t["name"]); !ok {
		bad("%s: name is not a string", label)
		return
	}
	entries, ok1 := asList(t["entries"])
	paths, ok2 := asList(t["paths"])
	rootText, ok3 := asString(t["root"])
	size, k1 := classifyUint(t["tree_size"])
	depth, k2 := classifyUint(t["depth"])
	switch {
	case !ok1 || !ok2:
		bad("%s: entries or paths is not a list", label)
		return
	case !ok3:
		bad("%s: root is not a string", label)
		return
	case k1 != intU64 || k2 != intU64:
		bad("%s: tree_size or depth is not an unsigned 64-bit integer", label)
		return
	}
	root, err := dec32(rootText)
	if err != nil {
		bad("%s: root: %v", label, err)
		return
	}
	if uint64(len(entries)) != size {
		bad("%s: %d entries, tree_size %d", label, len(entries), size)
		return
	}
	if len(entries) > 0 && len(paths) == 0 {
		bad("%s: %d entries and no paths", label, len(entries))
		return
	}
	type entry struct {
		key    string
		digest h32
	}
	ents := make([]entry, 0, len(entries))
	for ei, er := range entries {
		e, ok := asObject(er)
		if !ok {
			bad("%s: entries[%d] is not an object", label, ei)
			return
		}
		key, ok1 := asString(e["key"])
		dtext, ok2 := asString(e["digest"])
		if !ok1 || !ok2 {
			bad("%s: entries[%d]: key or digest is missing or not a string", label, ei)
			return
		}
		d, err := dec32(dtext)
		if err != nil {
			bad("%s: entries[%d]: digest: %v", label, ei, err)
			return
		}
		ents = append(ents, entry{key, d})
	}
	sort.SliceStable(ents, func(i, j int) bool { return ents[i].key < ents[j].key })
	position := map[string]uint64{}
	for i, e := range ents {
		if _, dup := position[e.key]; dup {
			bad("%s: key %q appears twice", label, e.key)
			return
		}
		position[e.key] = uint64(i)
	}

	// The leaves: each digest's 32 bytes, in key order.
	D := make([][]byte, len(ents))
	lhs := make([][]byte, len(ents))
	store := cn.NewMemStore()
	for i, e := range ents {
		D[i] = append([]byte(nil), e.digest[:]...)
		lhs[i] = refLeaf(D[i])
		cn.Append(store, D[i])
	}
	if size == 0 {
		cc.emptyTrees++
	}
	if got := cn.MTH(D); got != root {
		bad("%s: merkletree.MTH gives %s, the vectors say %s", label, hx32(got), rootText)
	}
	if got := cn.Root(store); got != root {
		bad("%s: merkletree.Append/Root gives %s, the vectors say %s", label, hx32(got), rootText)
	}
	if got := refMTH(lhs); !bytes.Equal(got, root[:]) {
		bad("%s: the RFC 9162 reference gives %s, the vectors say %s", label, hx(got), rootText)
	}
	// depth: the longest path the module's prover gives for any leaf.
	longest := 0
	for i := uint64(0); i < size; i++ {
		if n := len(cn.InclusionProof(store, size-1, i)); n > longest {
			longest = n
		}
	}
	if uint64(longest) != depth {
		bad("%s: the longest merkletree.InclusionProof path has %d nodes, the vectors say depth %d", label, longest, depth)
	}
	if size > 0 {
		if got := cn.Depth(store); got < 0 || uint64(got) != depth {
			bad("%s: merkletree.Depth gives %d, the vectors say %d", label, got, depth)
		}
		cc.depthByDepth++
	}

	for pi, pr := range paths {
		cc.paths++
		p, ok := asObject(pr)
		if !ok {
			bad("%s paths[%d] is not an object", label, pi)
			continue
		}
		plabel := fmt.Sprintf("%s paths[%d]", label, pi)
		if m := missing(p, "key", "digest", "leaf_index", "tree_size", "path", "binary_hex"); len(m) > 0 {
			bad("%s: missing %s", plabel, strings.Join(m, ", "))
			continue
		}
		key, ok1 := asString(p["key"])
		dtext, ok2 := asString(p["digest"])
		bhex, ok3 := asString(p["binary_hex"])
		texts, ok4 := asStrings(p["path"])
		if !ok1 || !ok2 || !ok3 || !ok4 {
			bad("%s: key, digest or binary_hex is not a string, or path is not a list of strings", plabel)
			continue
		}
		plabel = fmt.Sprintf("%s path for key %q", label, key)
		idx, k1 := classifyUint(p["leaf_index"])
		psize, k2 := classifyUint(p["tree_size"])
		if k1 != intU64 || k2 != intU64 {
			bad("%s: leaf_index or tree_size is not an unsigned 64-bit integer", plabel)
			continue
		}
		digest, err := dec32(dtext)
		if err != nil {
			bad("%s: digest: %v", plabel, err)
			continue
		}
		nodes, err := decNodes(texts)
		if err != nil {
			bad("%s: path %v", plabel, err)
			continue
		}
		pos, known := position[key]
		switch {
		case psize != size:
			bad("%s: tree_size %d in a tree of %d", plabel, psize, size)
			continue
		case !known || pos != idx || ents[pos].digest != digest:
			bad("%s: leaf_index %d or digest does not match the key's entry in byte order", plabel, idx)
			continue
		}
		if !eqPath(cn.MPath(idx, D), nodes) {
			bad("%s: differs from merkletree.MPath(%d, leaves)", plabel, idx)
		}
		if !eqPath(cn.InclusionProof(store, size-1, idx), nodes) {
			bad("%s: differs from merkletree.InclusionProof(store, %d, %d)", plabel, size-1, idx)
		}
		leaf := cn.LeafHash(digest[:])
		if !verify(nodes, idx, size, root, leaf) {
			bad("%s: merkletree.Path.VerifyInclusion(%d, %d, root, LeafHash(digest)) refuses it", plabel, size-1, idx)
		}
		if !eqByteSlices(refPath(idx, lhs), slices(nodes)) || !refVerify(leaf[:], idx, size, slices(nodes), root[:]) {
			bad("%s: the RFC 9162 reference disagrees", plabel)
		}
		if bhex != binaryForm(idx, size, nodes) {
			bad("%s: binary_hex does not encode leaf_index, tree_size and path", plabel)
		}
	}
}

func eqByteSlices(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func evaluateOursAccept(raw json.RawMessage, ai int, cc *oursCounts, bad failer) {
	a, ok := asObject(raw)
	if !ok {
		bad("walk_accepts[%d] is not an object", ai)
		return
	}
	label := nameOf(a, "walk_accepts", ai)
	if m := missing(a, "name", "digest", "proof", "max_steps", "root", "binary_hex"); len(m) > 0 {
		bad("%s: missing %s", label, strings.Join(m, ", "))
		return
	}
	name, ok1 := asString(a["name"])
	dtext, ok2 := asString(a["digest"])
	rtext, ok3 := asString(a["root"])
	bhex, ok4 := asString(a["binary_hex"])
	if !ok1 || !ok2 || !ok3 || !ok4 {
		bad("%s: name, digest, root or binary_hex is not a string", label)
		return
	}
	if _, k := classifyUint(a["max_steps"]); k == intNot {
		bad("%s: max_steps is not an integer", label)
		return
	}
	proof, ok := asObject(a["proof"])
	if !ok {
		bad("%s: proof is not an object", label)
		return
	}
	if m := missing(proof, "leaf_index", "tree_size", "path"); len(m) > 0 {
		bad("%s: proof: missing %s", label, strings.Join(m, ", "))
		return
	}
	texts, ok := asStrings(proof["path"])
	if !ok {
		bad("%s: proof.path is not a list of strings", label)
		return
	}
	idx, k1 := classifyUint(proof["leaf_index"])
	size, k2 := classifyUint(proof["tree_size"])
	switch {
	case k1 == intNot || k2 == intNot:
		bad("%s: proof.leaf_index or proof.tree_size is not an integer", label)
		return
	case k1 == intNegative || k2 == intNegative:
		bad("%s: proof.leaf_index or proof.tree_size is negative, which no proof can accept", label)
		return
	case k2 == intU64 && size == 0:
		bad("%s: proof.tree_size is 0, which no proof can accept", label)
		return
	}
	digest, err := dec32(dtext)
	if err != nil {
		bad("%s: digest: %v", label, err)
		return
	}
	root, err := dec32(rtext)
	if err != nil {
		bad("%s: root: %v", label, err)
		return
	}
	nodes, err := decNodes(texts)
	if err != nil {
		bad("%s: proof.path %v", label, err)
		return
	}
	if k1 == intTooBig || k2 == intTooBig {
		// VerifyInclusion takes i and at = tree_size - 1 as uint64 values.
		cc.acceptSkips = append(cc.acceptSkips, strconv.Quote(name)+": proof.leaf_index or proof.tree_size is above 2^64 - 1, which merkletree's uint64 arguments cannot hold")
		return
	}
	leaf := cn.LeafHash(digest[:])
	if !verify(nodes, idx, size, root, leaf) {
		bad("%s: merkletree.Path.VerifyInclusion(%d, %d, root, LeafHash(digest)) refuses it", label, size-1, idx)
	}
	if !refVerify(leaf[:], idx, size, slices(nodes), root[:]) {
		bad("%s: the RFC 9162 reference refuses it", label)
	}
	if bhex != binaryForm(idx, size, nodes) {
		bad("%s: binary_hex does not encode leaf_index, tree_size and path", label)
	}
	cc.accepts++
}

// hexBytes decodes hex text in either case; ok is false when the text is not
// hex, so that no byte value exists.
func hexBytes(s string) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	return b, err == nil
}

func evaluateOursRefusal(raw json.RawMessage, ri int, cc *oursCounts, bad failer) {
	r, ok := asObject(raw)
	if !ok {
		bad("walk_refusals[%d] is not an object", ri)
		return
	}
	label := nameOf(r, "walk_refusals", ri)
	// A refusal case may hold any value on purpose (a null digest, a proof
	// that is not an object), so only the presence of these members is
	// required of every case.
	var absent []string
	for _, n := range []string{"name", "digest", "proof", "max_steps", "error"} {
		if _, ok := r[n]; !ok {
			absent = append(absent, n)
		}
	}
	if len(absent) > 0 {
		bad("%s: missing %s", label, strings.Join(absent, ", "))
		return
	}
	name, ok1 := asString(r["name"])
	errText, ok2 := asString(r["error"])
	if !ok1 || !ok2 {
		bad("%s: name or error is not a string", label)
		return
	}
	switch errText {
	case "index_out_of_range", "wrong_path_length":
	default:
		cc.outOfScope[errText]++
		return
	}

	// An in-scope case is checked, so every field it uses must have its JSON
	// type; only a non-hex value or an integer outside uint64 is skipped.
	dtext, ok := asString(r["digest"])
	if !ok {
		bad("%s: digest is not a string", label)
		return
	}
	if _, k := classifyUint(r["max_steps"]); k == intNot {
		bad("%s: max_steps is not an integer", label)
		return
	}
	proof, ok := asObject(r["proof"])
	if !ok {
		bad("%s: proof is not an object", label)
		return
	}
	if m := missing(proof, "leaf_index", "tree_size", "path"); len(m) > 0 {
		bad("%s: proof: missing %s", label, strings.Join(m, ", "))
		return
	}
	texts, ok := asStrings(proof["path"])
	if !ok {
		bad("%s: proof.path is not a list of strings", label)
		return
	}
	idx, k1 := classifyUint(proof["leaf_index"])
	size, k2 := classifyUint(proof["tree_size"])
	if k1 == intNot || k2 == intNot {
		bad("%s: proof.leaf_index or proof.tree_size is not an integer", label)
		return
	}

	skip := func(reason string) { cc.refusalSkips = append(cc.refusalSkips, strconv.Quote(name)+": "+reason) }
	d, isHex := hexBytes(dtext)
	if !isHex {
		skip("the digest is not hex")
		return
	}
	if len(d) != sha256.Size {
		bad("%s: digest is hex but %d bytes, not 32", label, len(d))
		return
	}
	nodes := make([][sha256.Size]byte, len(texts))
	for i, s := range texts {
		b, isHex := hexBytes(s)
		if !isHex {
			skip(fmt.Sprintf("path node %d is not hex", i))
			return
		}
		if len(b) != sha256.Size {
			bad("%s: path node %d is hex but %d bytes; merkletree.Path holds 32-byte nodes", label, i, len(b))
			return
		}
		copy(nodes[i][:], b)
	}
	if k1 != intU64 || k2 != intU64 || size == 0 {
		skip("proof.leaf_index or at = proof.tree_size - 1 is outside the uint64 range merkletree's arguments hold")
		return
	}

	leaf := cn.LeafHash(d)
	chain := refChainUnchecked(leaf[:], idx, size, slices(nodes))
	var root h32
	copy(root[:], chain)
	if refVerify(leaf[:], idx, size, slices(nodes), chain) {
		bad("%s: the RFC 9162 reference accepts it", label)
		return
	}
	got := verify(nodes, idx, size, root, leaf)
	switch errText {
	case "index_out_of_range":
		if idx < size {
			bad("%s: error index_out_of_range, but leaf_index %d < tree_size %d", label, idx, size)
			return
		}
		if got {
			bad("%s: merkletree.Path.VerifyInclusion accepts leaf_index %d of tree_size %d", label, idx, size)
			return
		}
		cc.refusedIndex++
	case "wrong_path_length":
		if idx >= size {
			bad("%s: error wrong_path_length, but leaf_index %d >= tree_size %d", label, idx, size)
			return
		}
		if want := len(refRanges(idx, size)) - 1; want == len(nodes) {
			bad("%s: error wrong_path_length, but the path has the %d nodes RFC 9162 asks for", label, want)
			return
		}
		if got {
			cc.laxAccepted++
			cc.laxNames = append(cc.laxNames, strconv.Quote(name))
		} else {
			cc.refusedLength++
		}
	}
}
