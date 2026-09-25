// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// -ours <path> checks truestamp_merkle's own known answers (vectors/merkle.json,
// written by vectors/generate.exs) with golang.org/x/mod/sumdb/tlog. The leaf
// data of an entry is the 32 raw bytes of its digest, so its leaf hash is
// tlog.RecordHash(digest) = SHA-256(0x00 || digest), and a tree's leaves are
// its entries sorted by key, byte-wise ascending. With tlog's own functions:
//
//   - constants.empty_root is tlog.TreeHash(0, nil);
//   - every tree's root is tlog.TreeHash over the stored hashes that
//     tlog.StoredHashes builds from the sorted digests, the empty tree
//     included, and its depth is the length of the longest tlog.ProveRecord
//     path (0 for the empty tree, which has none);
//   - every listed path equals tlog.ProveRecord's, and tlog.CheckRecord
//     accepts it against the tree's root;
//   - tlog.CheckRecord accepts every walk_accepts case against its root;
//   - every walk_refusals case whose error is index_out_of_range or
//     wrong_path_length is refused by tlog.CheckRecord against both roots a
//     verifier without those checks would reach: the RFC 9162 section 2.1.3.2
//     loop with its checks removed, and the index-bit fold. The refusal must
//     come from tlog's input check for index_out_of_range and from its proof
//     run for wrong_path_length. tlog is strict, so the number it accepts must
//     be oursLaxAccepted, which is 0.
//
// The file must hold constants, trees, walk_accepts and walk_refusals, each
// present and non-empty, and every tree with entries must list paths.
// Members this program does not read are ignored, so a new member does not
// break it. A member it reads that is missing or has the wrong type is a
// failure, never a skip. Only two things are skipped, each counted and named
// on the OK line, and the counts are pinned (oursSkippedAccepts,
// oursSkippedRefusals), so a new skip fails until it is looked at:
//
//   - a walk_refusals digest or path node that is not hex, which has no byte
//     value to hand tlog;
//   - an integer tlog's API cannot represent: a leaf_index or tree_size
//     outside int64, or a tree_size above 2^62 where tlog.CheckRecord does
//     not return (see tlogMaxTreeSize).
//
// entry_refusals, binary_hex, binary_refusals, max_steps and the walk_refusals
// with other errors (invalid_leaf, invalid_node, invalid_proof,
// too_many_steps) concern the library's keys, text and binary encodings and
// step cap, which tlog has no counterpart for. They are counted as not
// applicable.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

const (
	// oursLaxAccepted is how many in-scope walk_refusals cases tlog.CheckRecord
	// may accept. Any other count fails, so a change in either side is caught.
	oursLaxAccepted = 0
	// oursSkippedAccepts is how many walk_accepts cases tlog cannot take, because
	// their tree_size does not fit int64: "64 steps under the default cap",
	// "the last of 2^63 + 1 entries", "index 2^64 - 2 of 2^64 - 1 entries" and
	// "index 2^63 - 1 of 2^64 - 1 entries".
	oursSkippedAccepts = 4
	// oursSkippedRefusals is how many in-scope walk_refusals cases tlog cannot
	// take: "the path length is checked before any node", whose path node
	// "bad" is not hex.
	oursSkippedRefusals = 1
)

type oursRun struct {
	errs []string

	emptyRoot                                    int
	trees, emptyTrees, entries                   int
	depths, paths                                int
	accepts                                      int
	acceptSkips                                  []string
	inScope, refused, lax                        int
	byError                                      map[string]int
	refusalSkips, laxNames                       []string
	otherRefusals, entryRefusals, binaryRefusals int
}

func (r *oursRun) fail(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

// checkOurs reads the vectors at path and checks them. It returns the OK
// line, or the failures.
func checkOurs(path string) (string, []string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", []string{"read: " + err.Error()}
	}
	doc, err := asObject(raw)
	if err != nil {
		return "", []string{fmt.Sprintf("parse %s: %v", path, err)}
	}
	r := &oursRun{byError: map[string]int{}}
	r.checkConstants(doc)
	r.checkTrees(doc)
	r.checkWalkAccepts(doc)
	r.checkWalkRefusals(doc)
	r.countNotApplicable(doc)
	if len(r.errs) > 0 {
		return "", r.errs
	}
	return fmt.Sprintf("OK ours %s: empty_root %d; trees %d (empty %d), %d entries, roots %d/%d by tlog.TreeHash over tlog.StoredHashes of the digests sorted by key, depth %d/%d as the longest tlog.ProveRecord path; paths %d, each equal to tlog.ProveRecord and accepted by tlog.CheckRecord; walk_accepts %d accepted by tlog.CheckRecord, %d skipped as tlog cannot take an integer (%s); walk_refusals index_out_of_range %d and wrong_path_length %d: %d refused by tlog.CheckRecord against both unchecked-chain roots, each by the matching tlog check, %d skipped as a value is not hex (%s), accepted %d (lax constant %d); not applicable to tlog: %d other walk_refusals, %d entry_refusals, %d binary_refusals, binary_hex, max_steps",
		moduleID, r.emptyRoot, r.trees, r.emptyTrees, r.entries, r.trees, r.trees, r.depths, r.trees, r.paths,
		r.accepts, len(r.acceptSkips), strings.Join(r.acceptSkips, "; "),
		r.byError["index_out_of_range"], r.byError["wrong_path_length"], r.refused,
		len(r.refusalSkips), strings.Join(r.refusalSkips, "; "), r.lax, oursLaxAccepted,
		r.otherRefusals, r.entryRefusals, r.binaryRefusals), nil
}

func (r *oursRun) checkConstants(doc jsonObject) {
	c, err := doc.object("constants")
	if err != nil {
		r.fail("%v", err)
		return
	}
	if len(c) == 0 {
		r.fail("\"constants\" is empty")
		return
	}
	want, err := c.hash("empty_root")
	if err != nil {
		r.fail("constants: %v", err)
		return
	}
	got, err := tlog.TreeHash(0, nil)
	if err != nil || got != want {
		r.fail("constants.empty_root: tlog.TreeHash(0, nil) = %s, %v; vectors have %s", hx(got), err, hx(want))
		return
	}
	r.emptyRoot++
}

type oursEntry struct {
	key    string
	digest tlog.Hash
}

func (r *oursRun) checkTrees(doc jsonObject) {
	trees, err := doc.nonEmptyArray("trees")
	if err != nil {
		r.fail("%v", err)
		return
	}
	for i, raw := range trees {
		r.checkTree(i, raw)
	}
	if r.paths == 0 && len(r.errs) == 0 {
		r.fail("trees: no path to check")
	}
}

func (r *oursRun) checkTree(i int, raw json.RawMessage) {
	label := fmt.Sprintf("trees[%d]", i)
	t, err := asObject(raw)
	if err != nil {
		r.fail("%s: %v", label, err)
		return
	}
	name, err := t.str("name")
	if err != nil {
		r.fail("%s: %v", label, err)
		return
	}
	label = fmt.Sprintf("tree %q", name)

	rawEntries, err := t.array("entries")
	if err != nil {
		r.fail("%s: %v", label, err)
		return
	}
	entries := make([]oursEntry, 0, len(rawEntries))
	for j, re := range rawEntries {
		e, err := asObject(re)
		if err != nil {
			r.fail("%s entries[%d]: %v", label, j, err)
			return
		}
		key, err1 := e.str("key")
		d, err2 := e.hash("digest")
		if err := firstErr(err1, err2); err != nil {
			r.fail("%s entries[%d]: %v", label, j, err)
			return
		}
		entries = append(entries, oursEntry{key, d})
	}
	sort.SliceStable(entries, func(a, b int) bool { return entries[a].key < entries[b].key })
	for j := 1; j < len(entries); j++ {
		if entries[j].key == entries[j-1].key {
			r.fail("%s: key %q appears twice", label, entries[j].key)
			return
		}
	}
	size, err1 := t.int64Member("tree_size")
	root, err2 := t.hash("root")
	depth, err3 := t.int64Member("depth")
	rawPaths, err4 := t.array("paths")
	if err := firstErr(err1, err2, err3, err4); err != nil {
		r.fail("%s: %v", label, err)
		return
	}
	if size != int64(len(entries)) {
		r.fail("%s: tree_size %d for %d entries", label, size, len(entries))
		return
	}
	if size > 0 && len(rawPaths) == 0 {
		r.fail("%s: %d entries but no paths", label, size)
		return
	}

	// tlog's tree builder: StoredHashes takes a record's data, here the digest.
	var s storage
	for j, e := range entries {
		hs, err := tlog.StoredHashes(int64(j), e.digest[:], s)
		if err != nil {
			r.fail("%s: tlog.StoredHashes(%d): %v", label, j, err)
			return
		}
		s = append(s, hs...)
	}
	got, err := tlog.TreeHash(size, s)
	if err != nil || got != root {
		r.fail("%s: tlog.TreeHash(%d) = %s, %v; vectors have %s", label, size, hx(got), err, hx(root))
		return
	}

	// depth: the longest tlog.ProveRecord path, 0 for the empty tree.
	proofs := make([]tlog.RecordProof, size)
	longest := 0
	for m := int64(0); m < size; m++ {
		p, err := tlog.ProveRecord(size, m, s)
		if err != nil {
			r.fail("%s: tlog.ProveRecord(%d, %d): %v", label, size, m, err)
			return
		}
		proofs[m] = p
		longest = max(longest, len(p))
	}
	if int64(longest) != depth {
		r.fail("%s: depth %d, but the longest tlog.ProveRecord path has %d hashes", label, depth, longest)
		return
	}
	r.trees++
	r.depths++
	r.entries += len(entries)
	if size == 0 {
		r.emptyTrees++
	}

	for k, rp := range rawPaths {
		pl := fmt.Sprintf("%s paths[%d]", label, k)
		po, err := asObject(rp)
		if err != nil {
			r.fail("%s: %v", pl, err)
			continue
		}
		key, err1 := po.str("key")
		digest, err2 := po.hash("digest")
		idx, err3 := po.int64Member("leaf_index")
		psize, err4 := po.int64Member("tree_size")
		path, err5 := po.hashes("path")
		if err := firstErr(err1, err2, err3, err4, err5); err != nil {
			r.fail("%s: %v", pl, err)
			continue
		}
		pl = fmt.Sprintf("%s path of %q", label, key)
		switch {
		case psize != size:
			r.fail("%s: tree_size %d, the tree has %d", pl, psize, size)
		case idx < 0 || idx >= size:
			r.fail("%s: leaf_index %d outside the tree", pl, idx)
		case entries[idx].key != key || entries[idx].digest != digest:
			r.fail("%s: not the entry at leaf_index %d once the entries are sorted by key", pl, idx)
		case !equalProof(tlog.RecordProof(path), proofs[idx]):
			r.fail("%s: path differs from tlog.ProveRecord(%d, %d)", pl, size, idx)
		default:
			if err := tlog.CheckRecord(path, size, root, idx, tlog.RecordHash(digest[:])); err != nil {
				r.fail("%s: tlog.CheckRecord refuses it: %v", pl, err)
				continue
			}
			r.paths++
		}
	}
}

func (r *oursRun) checkWalkAccepts(doc jsonObject) {
	cases, err := doc.nonEmptyArray("walk_accepts")
	if err != nil {
		r.fail("%v", err)
		return
	}
	for i, raw := range cases {
		label := fmt.Sprintf("walk_accepts[%d]", i)
		w, err := asObject(raw)
		if err != nil {
			r.fail("%s: %v", label, err)
			continue
		}
		name, err := w.str("name")
		if err != nil {
			r.fail("%s: %v", label, err)
			continue
		}
		label = fmt.Sprintf("walk_accepts %q", name)
		digest, err1 := w.hash("digest")
		root, err2 := w.hash("root")
		proof, err3 := w.object("proof")
		if err := firstErr(err1, err2, err3); err != nil {
			r.fail("%s: %v", label, err)
			continue
		}
		idx, idxFits, err1 := proof.integer("leaf_index")
		size, sizeFits, err2 := proof.integer("tree_size")
		path, err3 := proof.hashes("path")
		if err := firstErr(err1, err2, err3); err != nil {
			r.fail("%s proof: %v", label, err)
			continue
		}
		switch {
		case !idxFits || !sizeFits:
			r.acceptSkips = append(r.acceptSkips, strconv.Quote(name)+": leaf_index or tree_size outside int64")
			continue
		case !tlogReturns(size, idx, len(path)):
			r.acceptSkips = append(r.acceptSkips, strconv.Quote(name)+": tree_size above 2^62, where tlog.CheckRecord does not return")
			continue
		}
		if err := tlog.CheckRecord(path, size, root, idx, tlog.RecordHash(digest[:])); err != nil {
			r.fail("%s: tlog.CheckRecord refuses it: %v", label, err)
			continue
		}
		r.accepts++
	}
	if len(r.acceptSkips) != oursSkippedAccepts {
		r.fail("walk_accepts: %d cases skipped, expected %d%s", len(r.acceptSkips), oursSkippedAccepts, listed(r.acceptSkips))
	}
	if r.accepts == 0 {
		r.fail("walk_accepts: no case accepted by tlog.CheckRecord")
	}
}

// refusalHash reads member k of an in-scope walk_refusals case. It must be a
// string. A string that is not hex has no byte value, so it gives skip; hex
// of any length but 32 bytes is a failure, since tlog.Hash holds 32.
func refusalHash(k, s string) (h tlog.Hash, skip bool, err error) {
	b, derr := hex.DecodeString(s)
	switch {
	case derr != nil:
		return h, true, nil
	case len(b) != tlog.HashSize:
		return h, false, fmt.Errorf("%s %q is %d bytes of hex, not %d", k, s, len(b), tlog.HashSize)
	}
	copy(h[:], b)
	return h, false, nil
}

func (r *oursRun) checkWalkRefusals(doc jsonObject) {
	cases, err := doc.nonEmptyArray("walk_refusals")
	if err != nil {
		r.fail("%v", err)
		return
	}
	// tlog's two refusals, taken from tlog itself: the input check
	// (leaf_index >= tree_size) and the proof run (here, a hash too many for a
	// tree of one leaf).
	inputsErr := tlog.CheckRecord(nil, 1, tlog.Hash{}, 1, tlog.Hash{})
	proofErr := tlog.CheckRecord(tlog.RecordProof{{}}, 1, tlog.Hash{}, 0, tlog.Hash{})
	if inputsErr == nil || proofErr == nil || inputsErr.Error() == proofErr.Error() {
		r.fail("walk_refusals: cannot tell tlog's input check from its proof run (%v, %v)", inputsErr, proofErr)
		return
	}
	for i, raw := range cases {
		label := fmt.Sprintf("walk_refusals[%d]", i)
		w, err := asObject(raw)
		if err != nil {
			r.fail("%s: %v", label, err)
			continue
		}
		name, err1 := w.str("name")
		kind, err2 := w.str("error")
		if err := firstErr(err1, err2); err != nil {
			r.fail("%s: %v", label, err)
			continue
		}
		label = fmt.Sprintf("walk_refusals %q", name)
		var want error
		var which string
		switch kind {
		case "index_out_of_range":
			want, which = inputsErr, "input check"
		case "wrong_path_length":
			want, which = proofErr, "proof run"
		default:
			r.otherRefusals++
			continue
		}
		r.inScope++
		r.byError[kind]++

		// Every member is read and type-checked first, so a malformed one
		// fails even in a case that is then skipped.
		var notHex []string
		digestText, err := w.str("digest")
		if err != nil {
			r.fail("%s: %v", label, err)
			continue
		}
		digest, skip, err := refusalHash("digest", digestText)
		if err != nil {
			r.fail("%s: %v", label, err)
			continue
		}
		if skip {
			notHex = append(notHex, "digest "+strconv.Quote(digestText))
		}
		proof, err := w.object("proof")
		if err != nil {
			r.fail("%s: %v", label, err)
			continue
		}
		idx, idxFits, err1 := proof.integer("leaf_index")
		size, sizeFits, err2 := proof.integer("tree_size")
		rawPath, err3 := proof.array("path")
		if err := firstErr(err1, err2, err3); err != nil {
			r.fail("%s proof: %v", label, err)
			continue
		}
		path := make([]tlog.Hash, 0, len(rawPath))
		bad := false
		for j, rn := range rawPath {
			var s string
			t := bytes.TrimSpace(rn)
			if len(t) == 0 || t[0] != '"' || json.Unmarshal(t, &s) != nil {
				r.fail("%s proof: path[%d] is not a string", label, j)
				bad = true
				break
			}
			h, skip, err := refusalHash(fmt.Sprintf("path[%d]", j), s)
			if err != nil {
				r.fail("%s proof: %v", label, err)
				bad = true
				break
			}
			if skip {
				notHex = append(notHex, fmt.Sprintf("path[%d] %q", j, s))
			}
			path = append(path, h)
		}
		if bad {
			continue
		}
		skipAs := func(why string) {
			r.refusalSkips = append(r.refusalSkips, strconv.Quote(name)+": "+why)
		}
		switch {
		case len(notHex) > 0:
			skipAs(strings.Join(notHex, " and ") + " not hex")
			continue
		case !idxFits || !sizeFits:
			skipAs("leaf_index or tree_size outside int64")
			continue
		case !tlogReturns(size, idx, len(path)):
			skipAs("tree_size above 2^62, where tlog.CheckRecord does not return")
			continue
		}
		leaf := tlog.RecordHash(digest[:])
		accepted := false
		for _, root := range []tlog.Hash{uncheckedChain(idx, size, leaf, path), indexBitFold(idx, leaf, path)} {
			err := tlog.CheckRecord(path, size, root, idx, leaf)
			switch {
			case err == nil:
				accepted = true
			case err.Error() != want.Error():
				r.fail("%s (%s): tlog.CheckRecord refuses with %q, not with its %s refusal %q", label, kind, err, which, want)
			}
		}
		if accepted {
			r.lax++
			r.laxNames = append(r.laxNames, name)
		} else {
			r.refused++
		}
	}
	if r.lax != oursLaxAccepted {
		r.fail("walk_refusals: tlog.CheckRecord accepts %d in-scope cases, expected %d%s", r.lax, oursLaxAccepted, listed(r.laxNames))
	}
	if len(r.refusalSkips) != oursSkippedRefusals {
		r.fail("walk_refusals: %d in-scope cases skipped, expected %d%s", len(r.refusalSkips), oursSkippedRefusals, listed(r.refusalSkips))
	}
	if r.refused == 0 {
		r.fail("walk_refusals: no index_out_of_range or wrong_path_length case refused by tlog.CheckRecord")
	}
}

// listed is ": a; b" for a non-empty list, else "".
func listed(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return ": " + strings.Join(names, "; ")
}

func (r *oursRun) countNotApplicable(doc jsonObject) {
	for _, sec := range []struct {
		key string
		n   *int
	}{{"entry_refusals", &r.entryRefusals}, {"binary_refusals", &r.binaryRefusals}} {
		if _, ok := doc[sec.key]; !ok {
			continue
		}
		a, err := doc.array(sec.key)
		if err != nil {
			r.fail("%v", err)
			continue
		}
		*sec.n = len(a)
	}
}

// uncheckedChain is the RFC 9162 section 2.1.3.2 loop with its checks
// removed (no leaf_index < tree_size check, no path length rules), hashing
// with tlog.NodeHash: the root a verifier without those checks reaches.
func uncheckedChain(index, size int64, leaf tlog.Hash, path []tlog.Hash) tlog.Hash {
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if fn&1 == 1 || fn == sn {
			r = tlog.NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = tlog.NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return r
}

// indexBitFold is the fold that looks only at the index bits: the leaf's
// side at each level is bit k of leaf_index.
func indexBitFold(index int64, leaf tlog.Hash, path []tlog.Hash) tlog.Hash {
	r := leaf
	for _, p := range path {
		if index&1 == 1 {
			r = tlog.NodeHash(p, r)
		} else {
			r = tlog.NodeHash(r, p)
		}
		index >>= 1
	}
	return r
}

// ---------- tolerant JSON access: every malformed value is an error ----------

type jsonObject map[string]json.RawMessage

func asObject(raw []byte) (jsonObject, error) {
	t := bytes.TrimSpace(raw)
	var m jsonObject
	if len(t) == 0 || t[0] != '{' || json.Unmarshal(t, &m) != nil || m == nil {
		return nil, fmt.Errorf("not a JSON object")
	}
	return m, nil
}

func (o jsonObject) member(k string) (json.RawMessage, error) {
	v, ok := o[k]
	if !ok {
		return nil, fmt.Errorf("no %q member", k)
	}
	return bytes.TrimSpace(v), nil
}

func (o jsonObject) object(k string) (jsonObject, error) {
	v, err := o.member(k)
	if err != nil {
		return nil, err
	}
	m, err := asObject(v)
	if err != nil {
		return nil, fmt.Errorf("%q is %v", k, err)
	}
	return m, nil
}

func (o jsonObject) str(k string) (string, error) {
	v, err := o.member(k)
	if err != nil {
		return "", err
	}
	var s string
	if len(v) == 0 || v[0] != '"' || json.Unmarshal(v, &s) != nil {
		return "", fmt.Errorf("%q is not a string", k)
	}
	return s, nil
}

func (o jsonObject) hash(k string) (tlog.Hash, error) {
	s, err := o.str(k)
	if err != nil {
		return tlog.Hash{}, err
	}
	h, err := parseHex(s)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("%q: %v", k, err)
	}
	return h, nil
}

// integer returns member k. fits is false for a JSON integer outside int64;
// anything that is not a JSON integer is an error.
func (o jsonObject) integer(k string) (n int64, fits bool, err error) {
	v, err := o.member(k)
	if err != nil {
		return 0, false, err
	}
	t := string(v)
	digits := strings.TrimPrefix(t, "-")
	if digits == "" || strings.Trim(digits, "0123456789") != "" || (digits[0] == '0' && len(digits) > 1) {
		return 0, false, fmt.Errorf("%q is not an integer", k)
	}
	n, perr := strconv.ParseInt(t, 10, 64)
	if perr != nil {
		return 0, false, nil
	}
	return n, true, nil
}

// int64Member is integer for members that must fit.
func (o jsonObject) int64Member(k string) (int64, error) {
	n, fits, err := o.integer(k)
	if err != nil {
		return 0, err
	}
	if !fits {
		return 0, fmt.Errorf("%q does not fit int64", k)
	}
	return n, nil
}

func (o jsonObject) array(k string) ([]json.RawMessage, error) {
	v, err := o.member(k)
	if err != nil {
		return nil, err
	}
	var a []json.RawMessage
	if len(v) == 0 || v[0] != '[' || json.Unmarshal(v, &a) != nil {
		return nil, fmt.Errorf("%q is not an array", k)
	}
	return a, nil
}

// nonEmptyArray is array for a section that must hold at least one case.
func (o jsonObject) nonEmptyArray(k string) ([]json.RawMessage, error) {
	a, err := o.array(k)
	if err != nil {
		return nil, err
	}
	if len(a) == 0 {
		return nil, fmt.Errorf("%q is empty", k)
	}
	return a, nil
}

func (o jsonObject) hashes(k string) ([]tlog.Hash, error) {
	a, err := o.array(k)
	if err != nil {
		return nil, err
	}
	out := make([]tlog.Hash, 0, len(a))
	for i, raw := range a {
		var s string
		t := bytes.TrimSpace(raw)
		if len(t) == 0 || t[0] != '"' || json.Unmarshal(t, &s) != nil {
			return nil, fmt.Errorf("%s[%d] is not a string", k, i)
		}
		h, err := parseHex(s)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %v", k, i, err)
		}
		out = append(out, h)
	}
	return out, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
