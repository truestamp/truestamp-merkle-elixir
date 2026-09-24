// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// -ours checks the truestamp_merkle library's own known answers
// (vectors/merkle.json, written by vectors/generate.exs) with sigsum-go's
// functions. An entry's leaf data is its digest's 32 raw bytes, so its leaf
// hash is merkle.HashLeafNode(digest), and a tree's entries are ordered by
// key, byte-wise ascending.
//
//   - constants.empty_root is merkle.HashEmptyTree() and
//     merkle.NewTree().GetRootHash().
//   - Every tree root is merkle.Tree's root over the ordered leaves, the empty
//     tree included. A tree with duplicate leaves (two keys with one digest)
//     cannot be a merkle.Tree, whose AddLeafHash refuses a repeat: its root is
//     built with sigsum's hash functions (sigsumMTH) and checked with
//     merkle.VerifyInclusionTail over all its leaves.
//   - Every leaf of every tree is proved (merkle.Tree.ProveInclusion, or
//     sigsumPath for a tree with duplicates) and verifies with
//     merkle.VerifyInclusion; depth is the longest of those paths.
//   - Every listed path verifies with merkle.VerifyInclusion, equals the
//     implementation's own path, and its binary_hex is the same proof.
//   - Every walk_accepts case verifies with merkle.VerifyInclusion. Sizes and
//     indexes are uint64 in sigsum-go, so every integer up to
//     constants.max_tree_size (2^64 - 1) is representable.
//   - Every walk_refusals case whose error is index_out_of_range or
//     wrong_path_length, and whose fields sigsum-go can represent, is refused
//     by merkle.VerifyInclusion for that reason, even against the root its
//     path reaches when chained with no checks at all.
//
// Not applicable to sigsum-go, so counted and not checked: max_steps
// (merkle.VerifyInclusion has no step cap), entry_refusals (no keyed entries)
// and binary_refusals (no binary proof form).
//
// Input. constants, trees, walk_accepts and walk_refusals must be present and
// non-empty, and a tree with entries must list paths. Members the program
// does not read are ignored, so a new field does not break the check. A
// member it reads that is missing, has the wrong JSON type or holds a
// malformed value fails the run. The only skips, each counted and named on
// the OK line, are an in-scope walk_refusals case with a node that is not 64
// hex digits (no crypto.Hash value exists; the library checks nodes after the
// index and the path length, so such a case is legitimate), and a case with
// an index or size over 2^64-1, which sigsum-go's uint64 cannot hold, when
// constants.max_tree_size is over 2^64-1 too. With the library's
// max_tree_size of 2^64-1, such an index or size fails the run instead.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"sigsum.org/sigsum-go/pkg/crypto"
	"sigsum.org/sigsum-go/pkg/merkle"
)

// laxAccepts is how many in-scope walk_refusals cases merkle.VerifyInclusion
// accepts. sigsum-go refuses index >= size, then any path whose length is not
// exactly the one the index and size need (pkg/merkle/verify.go:103-109), so
// it is 0 and any acceptance fails the run.
const laxAccepts = 0

// errUnrepresentable marks a JSON integer over 2^64-1, which sigsum-go's
// uint64 indexes and sizes cannot hold.
var errUnrepresentable = errors.New("an integer over 2^64-1")

var intLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

type jsonObject map[string]json.RawMessage

func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, []byte("null"))
}

// object decodes raw as a JSON object that has every member in keys. Other
// members are ignored, so a field added to the file later does not break the
// check.
func object(raw json.RawMessage, keys ...string) (jsonObject, error) {
	if isNull(raw) {
		return nil, errors.New("not an object")
	}
	var o jsonObject
	if err := json.Unmarshal(raw, &o); err != nil {
		return nil, fmt.Errorf("not an object: %v", err)
	}
	for _, k := range keys {
		if _, ok := o[k]; !ok {
			return nil, fmt.Errorf("missing member %q", k)
		}
	}
	return o, nil
}

func (o jsonObject) str(k string) (string, error) {
	var s string
	if isNull(o[k]) || json.Unmarshal(o[k], &s) != nil {
		return "", fmt.Errorf("%s is not a string", k)
	}
	return s, nil
}

// u64 decodes member k as a JSON integer. A negative one is an error; one
// over 2^64-1 gives an error wrapping errUnrepresentable.
func (o jsonObject) u64(k string) (uint64, error) {
	s := string(bytes.TrimSpace(o[k]))
	if !intLiteral.MatchString(s) {
		return 0, fmt.Errorf("%s is %.40s, not an integer", k, s)
	}
	if strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("%s is %.40s, a negative integer", k, s)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is %.40s: %w", k, s, errUnrepresentable)
	}
	return v, nil
}

// integer requires member k to be a JSON integer of any size. It is used for
// members sigsum-go has no counterpart for, such as max_steps.
func (o jsonObject) integer(k string) error {
	if s := string(bytes.TrimSpace(o[k])); !intLiteral.MatchString(s) {
		return fmt.Errorf("%s is %.40s, not an integer", k, s)
	}
	return nil
}

func (o jsonObject) list(k string) ([]json.RawMessage, error) {
	var l []json.RawMessage
	if isNull(o[k]) || json.Unmarshal(o[k], &l) != nil {
		return nil, fmt.Errorf("%s is not a list", k)
	}
	return l, nil
}

// hash decodes member k as 64 lowercase hex digits.
func (o jsonObject) hash(k string) (crypto.Hash, error) {
	s, err := o.str(k)
	if err != nil {
		return crypto.Hash{}, err
	}
	h, err := decodeHash(s)
	if err != nil {
		return crypto.Hash{}, fmt.Errorf("%s: %v", k, err)
	}
	return h, nil
}

// strs decodes member k as a list of strings.
func (o jsonObject) strs(k string) ([]string, error) {
	l, err := o.list(k)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for i, raw := range l {
		var s string
		if isNull(raw) || json.Unmarshal(raw, &s) != nil {
			return nil, fmt.Errorf("%s[%d] is not a string", k, i)
		}
		out = append(out, s)
	}
	return out, nil
}

// splitErrs separates the errors that only say an integer is over 2^64-1
// from every other error (which fails the case).
func splitErrs(errs ...error) (unrepresentable bool, hard error) {
	var h []error
	for _, e := range errs {
		switch {
		case e == nil:
		case errors.Is(e, errUnrepresentable):
			unrepresentable = true
		default:
			h = append(h, e)
		}
	}
	if len(h) > 0 {
		msgs := make([]string, len(h))
		for i, e := range h {
			msgs[i] = e.Error()
		}
		hard = errors.New(strings.Join(msgs, "; "))
	}
	return unrepresentable, hard
}

// hashes decodes member k as a list of 64-digit lowercase hex strings.
func (o jsonObject) hashes(k string) ([]crypto.Hash, error) {
	l, err := o.list(k)
	if err != nil {
		return nil, err
	}
	out := []crypto.Hash{}
	for i, raw := range l {
		var s string
		if isNull(raw) || json.Unmarshal(raw, &s) != nil {
			return nil, fmt.Errorf("%s[%d] is not a string", k, i)
		}
		h, err := decodeHash(s)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %v", k, i, err)
		}
		out = append(out, h)
	}
	return out, nil
}

// checkBinary requires binary_hex to be the library's binary form of the same
// proof: leaf_index and tree_size as 8-byte big-endian integers, then each
// 32-byte node.
func checkBinary(s string, index, size uint64, path []crypto.Hash) error {
	b, err := decodeBytes(s)
	if err != nil {
		return err
	}
	if len(b) != 16+32*len(path) {
		return fmt.Errorf("%d bytes, want %d", len(b), 16+32*len(path))
	}
	if binary.BigEndian.Uint64(b[:8]) != index || binary.BigEndian.Uint64(b[8:16]) != size {
		return errors.New("leaf_index or tree_size differs")
	}
	for i := range path {
		if !bytes.Equal(b[16+32*i:48+32*i], path[i][:]) {
			return fmt.Errorf("node %d differs", i)
		}
	}
	return nil
}

// chainRoot is the root a path reaches when its nodes are folded in by the
// RFC 9162 section 2.1.3.2 loop with none of its checks: no index check, no
// early stop at step 4a and no final check at step 5. A verifier that skipped
// those checks would accept the path against this root.
func chainRoot(leaf crypto.Hash, index, size uint64, path []crypto.Hash) crypto.Hash {
	fn, sn := index, uint64(0)
	if size > 0 {
		sn = size - 1
	}
	r := leaf
	for _, p := range path {
		if fn&1 == 1 || fn == sn {
			r = node(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = node(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return r
}

// checkOurs checks the library's vectors file. It returns the counts for the
// "OK ours" line, and one line per failure.
func checkOurs(file string) (string, []string) {
	var fails []string
	failf := func(format string, args ...any) { fails = append(fails, fmt.Sprintf(format, args...)) }

	raw, err := os.ReadFile(file)
	if err != nil {
		return "", []string{fmt.Sprintf("read %s: %v", file, err)}
	}
	top, err := object(raw, "description", "constants", "trees", "entry_refusals", "walk_accepts", "walk_refusals", "binary_refusals")
	if err != nil {
		return "", []string{fmt.Sprintf("decode %s: %v", file, err)}
	}
	if _, err := top.str("description"); err != nil {
		failf("%v", err)
	}

	// constants
	maxSizeFits := false
	if c, err := object(top["constants"], "empty_root", "max_steps", "max_tree_size"); err != nil {
		failf("constants: %v", err)
	} else {
		empty := merkle.NewTree()
		if er, err := c.hash("empty_root"); err != nil {
			failf("constants: %v", err)
		} else if er != merkle.HashEmptyTree() || er != empty.GetRootHash() {
			failf("constants: empty_root %s is not merkle.HashEmptyTree() = merkle.NewTree().GetRootHash() = %s", hh(er), hh(merkle.HashEmptyTree()))
		}
		if err := c.integer("max_steps"); err != nil {
			failf("constants: %v", err)
		}
		switch _, err := c.u64("max_tree_size"); {
		case err == nil:
			maxSizeFits = true
		case !errors.Is(err, errUnrepresentable):
			failf("constants: %v", err)
		}
	}

	// trees
	treeList, err := top.list("trees")
	if err != nil {
		failf("%v", err)
	} else if len(treeList) == 0 {
		failf("trees is empty")
	}
	type entry struct {
		key, digestHex string
		digest         crypto.Hash
	}
	builtByTree, emptyTrees, leavesProved := 0, 0, 0
	var dupNames []string
	pathsChecked, proverEqual, hasherEqual := 0, 0, 0
	for ti, traw := range treeList {
		t, err := object(traw, "name", "entries", "root", "depth", "tree_size", "paths")
		if err != nil {
			failf("trees[%d]: %v", ti, err)
			continue
		}
		name, err := t.str("name")
		if err != nil {
			failf("trees[%d]: %v", ti, err)
			continue
		}
		where := fmt.Sprintf("tree %q", name)
		entryList, err := t.list("entries")
		if err != nil {
			failf("%s: %v", where, err)
			continue
		}
		var es []entry
		bad := false
		for i, eraw := range entryList {
			e, err := object(eraw, "key", "digest")
			var key, dhex string
			var d crypto.Hash
			if err == nil {
				key, err = e.str("key")
			}
			if err == nil {
				dhex, err = e.str("digest")
			}
			if err == nil {
				d, err = decodeHash(dhex)
			}
			if err != nil {
				failf("%s entries[%d]: %v", where, i, err)
				bad = true
				continue
			}
			es = append(es, entry{key: key, digestHex: dhex, digest: d})
		}
		size, err1 := t.u64("tree_size")
		root, err2 := t.hash("root")
		depth, err3 := t.u64("depth")
		pathList, err4 := t.list("paths")
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			failf("%s: %v", where, err)
			bad = true
		}
		if bad {
			continue
		}
		if len(es) > 0 && len(pathList) == 0 {
			failf("%s: %d entries but paths is empty", where, len(es))
		}
		slices.SortStableFunc(es, func(a, b entry) int { return strings.Compare(a.key, b.key) })
		for i := 1; i < len(es); i++ {
			if es[i].key == es[i-1].key {
				failf("%s: key %q appears twice", where, es[i].key)
				bad = true
			}
		}
		if size != uint64(len(es)) {
			failf("%s: tree_size %d, but %d entries", where, size, len(es))
			bad = true
		}
		if bad {
			continue
		}
		leaves := make([]crypto.Hash, len(es))
		indexOf := map[string]int{}
		for i, e := range es {
			leaves[i] = merkle.HashLeafNode(e.digest[:])
			indexOf[e.key] = i
		}

		// The root, and the implementation's path for each leaf.
		var prove func(i int) ([]crypto.Hash, error)
		dupAt := firstDuplicate(leaves)
		switch {
		case len(leaves) == 0:
			tr := merkle.NewTree()
			if tr.GetRootHash() != root || merkle.HashEmptyTree() != root {
				failf("%s: merkle.NewTree().GetRootHash() is %s, file says %s", where, hh(tr.GetRootHash()), hh(root))
			}
			builtByTree++
			emptyTrees++
		case dupAt < 0:
			tr := merkle.NewTree()
			for i := range leaves {
				tr.AddLeafHash(&leaves[i])
			}
			if tr.GetRootHash() != root {
				failf("%s: merkle.Tree root %s, file says %s", where, hh(tr.GetRootHash()), hh(root))
			}
			prove = func(i int) ([]crypto.Hash, error) { return tr.ProveInclusion(uint64(i), size) }
			builtByTree++
		default:
			tr := merkle.NewTree()
			for i := 0; i < dupAt; i++ {
				tr.AddLeafHash(&leaves[i])
			}
			if tr.AddLeafHash(&leaves[dupAt]) {
				failf("%s: merkle.Tree.AddLeafHash accepted the repeated leaf %d", where, dupAt)
			}
			if sigsumMTH(leaves) != root {
				failf("%s: root built with sigsum's hash functions is %s, file says %s", where, hh(sigsumMTH(leaves)), hh(root))
			}
			if err := merkle.VerifyInclusionTail(slices.Clone(leaves), 0, &root, sigsumPath(0, leaves)); err != nil {
				failf("%s: merkle.VerifyInclusionTail over all %d leaves: %v", where, len(leaves), err)
			}
			prove = func(i int) ([]crypto.Hash, error) { return sigsumPath(i, leaves), nil }
			dupNames = append(dupNames, name)
		}

		// Every leaf, and depth.
		longest := 0
		for i := range leaves {
			p, err := prove(i)
			if err != nil {
				failf("%s: proving leaf %d: %v", where, i, err)
				continue
			}
			if !verify(leaves[i], uint64(i), size, root, p) {
				failf("%s: merkle.VerifyInclusion rejects the implementation's path for leaf %d", where, i)
			}
			longest = max(longest, len(p))
			leavesProved++
		}
		if depth != uint64(longest) {
			failf("%s: depth %d, but the longest audit path has %d nodes", where, depth, longest)
		}

		// The listed paths.
		for pi, praw := range pathList {
			pw := fmt.Sprintf("%s paths[%d]", where, pi)
			po, err := object(praw, "key", "digest", "leaf_index", "tree_size", "path", "binary_hex")
			if err != nil {
				failf("%s: %v", pw, err)
				continue
			}
			key, e1 := po.str("key")
			dhex, e2 := po.str("digest")
			li, e3 := po.u64("leaf_index")
			ts, e4 := po.u64("tree_size")
			p, e5 := po.hashes("path")
			bh, e6 := po.str("binary_hex")
			if err := errors.Join(e1, e2, e3, e4, e5, e6); err != nil {
				failf("%s: %v", pw, err)
				continue
			}
			idx, ok := indexOf[key]
			if !ok {
				failf("%s: key %q is not an entry", pw, key)
				continue
			}
			if dhex != es[idx].digestHex || li != uint64(idx) || ts != size {
				failf("%s: key %q is entry %d of %d with digest %s; the path says leaf_index %d, tree_size %d, digest %s", pw, key, idx, size, es[idx].digestHex, li, ts, dhex)
				continue
			}
			leaf := leaves[idx]
			if err := merkle.VerifyInclusion(&leaf, li, ts, &root, slices.Clone(p)); err != nil {
				failf("%s (key %q): merkle.VerifyInclusion: %v", pw, key, err)
			}
			if own, err := prove(idx); err != nil || !slices.Equal(own, p) {
				failf("%s (key %q): the path is not the implementation's own path for leaf %d (%v)", pw, key, idx, err)
			} else if dupAt < 0 {
				proverEqual++
			} else {
				hasherEqual++
			}
			if err := checkBinary(bh, li, ts, p); err != nil {
				failf("%s (key %q): binary_hex: %v", pw, key, err)
			}
			pathsChecked++
		}
	}

	// walk_accepts
	acceptList, err := top.list("walk_accepts")
	if err != nil {
		failf("%v", err)
	} else if len(acceptList) == 0 {
		failf("walk_accepts is empty")
	}
	acceptsVerified := 0
	var acceptsSkipped []string
	for ai, araw := range acceptList {
		a, err := object(araw, "name", "digest", "proof", "max_steps", "root", "binary_hex")
		if err != nil {
			failf("walk_accepts[%d]: %v", ai, err)
			continue
		}
		name, err := a.str("name")
		if err != nil {
			failf("walk_accepts[%d]: %v", ai, err)
			continue
		}
		where := fmt.Sprintf("walk_accepts %q", name)
		pr, err := object(a["proof"], "leaf_index", "tree_size", "path")
		if err != nil {
			failf("%s: proof: %v", where, err)
			continue
		}
		idx, e1 := pr.u64("leaf_index")
		size, e2 := pr.u64("tree_size")
		digest, e3 := a.hash("digest")
		path, e4 := pr.hashes("path")
		root, e5 := a.hash("root")
		e6 := a.integer("max_steps")
		bh, e7 := a.str("binary_hex")
		unrepresentable, hard := splitErrs(e1, e2, e3, e4, e5, e6, e7)
		if hard != nil {
			failf("%s: %v", where, hard)
			continue
		}
		if unrepresentable {
			// Skipped only when the library's own max_tree_size is over
			// 2^64-1 too; otherwise the case is beyond the library's limit.
			if maxSizeFits {
				failf("%s: an index or size over 2^64-1, beyond constants.max_tree_size", where)
			} else {
				acceptsSkipped = append(acceptsSkipped, fmt.Sprintf("%q", name))
			}
			continue
		}
		leaf := merkle.HashLeafNode(digest[:])
		if err := merkle.VerifyInclusion(&leaf, idx, size, &root, slices.Clone(path)); err != nil {
			failf("%s: merkle.VerifyInclusion: %v", where, err)
		} else {
			acceptsVerified++
		}
		if err := checkBinary(bh, idx, size, path); err != nil {
			failf("%s: binary_hex: %v", where, err)
		}
	}

	// walk_refusals
	refusalList, err := top.list("walk_refusals")
	if err != nil {
		failf("%v", err)
	} else if len(refusalList) == 0 {
		failf("walk_refusals is empty")
	}
	inScope, refused, otherErrors := 0, 0, 0
	var refusalsSkipped, accepted []string
	for ri, rraw := range refusalList {
		r, err := object(rraw, "name", "digest", "proof", "max_steps", "error")
		if err != nil {
			failf("walk_refusals[%d]: %v", ri, err)
			continue
		}
		name, e1 := r.str("name")
		want, e2 := r.str("error")
		e3 := r.integer("max_steps")
		if _, hard := splitErrs(e1, e2, e3); hard != nil {
			failf("walk_refusals[%d]: %v", ri, hard)
			continue
		}
		var fragment string
		switch want {
		case "index_out_of_range":
			fragment = errIndexOutOfRange
		case "wrong_path_length":
			fragment = errPathLength
		default:
			otherErrors++
			continue
		}
		inScope++
		where := fmt.Sprintf("walk_refusals %q", name)
		// A member that is missing or has the wrong JSON type fails the run,
		// and so does a digest that is not 64 lowercase hex digits: the
		// library checks the digest before the index and the path length, so
		// an in-scope case always has a valid one. A node is checked only
		// after both, so an in-scope case may carry a node that is not a hash;
		// one that is not 64 hex digits has no crypto.Hash value, so the case
		// is skipped and counted. So is an index or size over 2^64-1, but only
		// when constants.max_tree_size is over 2^64-1 too.
		pr, err := object(r["proof"], "leaf_index", "tree_size", "path")
		if err != nil {
			failf("%s: proof: %v", where, err)
			continue
		}
		digest, e1 := r.hash("digest")
		idx, e2 := pr.u64("leaf_index")
		size, e3 := pr.u64("tree_size")
		nodes, e4 := pr.strs("path")
		unrepresentable, hard := splitErrs(e1, e2, e3, e4)
		if hard != nil {
			failf("%s: %v", where, hard)
			continue
		}
		var why []string
		if unrepresentable {
			if maxSizeFits {
				failf("%s: an index or size over 2^64-1, beyond constants.max_tree_size", where)
				continue
			}
			why = append(why, "an index or size over 2^64-1")
		}
		path := make([]crypto.Hash, 0, len(nodes))
		for i, s := range nodes {
			h, err := crypto.HashFromHex(s)
			if err != nil {
				why = append(why, fmt.Sprintf("path[%d] %.20q is not 64 hex digits", i, s))
				continue
			}
			path = append(path, h)
		}
		if len(why) > 0 {
			refusalsSkipped = append(refusalsSkipped, fmt.Sprintf("%q (%s)", name, strings.Join(why, ", ")))
			continue
		}
		leaf := merkle.HashLeafNode(digest[:])
		root := chainRoot(leaf, idx, size, path)
		switch err := merkle.VerifyInclusion(&leaf, idx, size, &root, slices.Clone(path)); {
		case err == nil:
			accepted = append(accepted, name)
		case !strings.Contains(err.Error(), fragment):
			failf("%s: merkle.VerifyInclusion refused it for another reason than %s: %v", where, want, err)
		default:
			refused++
		}
	}
	if refused+len(accepted) == 0 && len(refusalList) > 0 {
		failf("walk_refusals: no index_out_of_range or wrong_path_length case could be checked")
	}
	if len(accepted) != laxAccepts {
		failf("walk_refusals: merkle.VerifyInclusion accepted %d in-scope cases against their chained roots, want %d: %q", len(accepted), laxAccepts, accepted)
	}

	// Not applicable to sigsum-go: counted only.
	entryRefusals, err := top.list("entry_refusals")
	if err != nil {
		failf("%v", err)
	}
	binaryRefusals, err := top.list("binary_refusals")
	if err != nil {
		failf("%v", err)
	}

	dups := "none"
	if len(dupNames) > 0 {
		dups = fmt.Sprintf("%q", dupNames)
	}
	skippedAccepts := "none"
	if len(acceptsSkipped) > 0 {
		skippedAccepts = strings.Join(acceptsSkipped, ", ")
	}
	skippedRefusals := "none"
	if len(refusalsSkipped) > 0 {
		skippedRefusals = strings.Join(refusalsSkipped, ", ")
	}
	summary := fmt.Sprintf("empty_root 1 (merkle.HashEmptyTree = merkle.NewTree().GetRootHash()); trees %d (root from merkle.Tree %d, the empty tree %d of them; duplicate leaves %d: %s, which merkle.Tree refuses, so the root is built with sigsum's hash functions and checked with merkle.VerifyInclusionTail); every leaf proved and verified %d, depth = longest path; paths %d (merkle.VerifyInclusion accepts all; equal to merkle.Tree.ProveInclusion %d, to the hash-function path %d; binary_hex agrees); walk_accepts %d (verified %d, skipped %d: %s; max_tree_size fits uint64: %v); walk_refusals index_out_of_range or wrong_path_length %d (refused for that reason against the chained root %d, skipped %d: %s; accepted %d, lax constant %d); not applicable: walk_refusals with other errors %d, entry_refusals %d, binary_refusals %d, max_steps (sigsum-go has no step cap)",
		len(treeList), builtByTree, emptyTrees, len(dupNames), dups, leavesProved, pathsChecked, proverEqual, hasherEqual,
		len(acceptList), acceptsVerified, len(acceptsSkipped), skippedAccepts, maxSizeFits,
		inScope, refused, len(refusalsSkipped), skippedRefusals, len(accepted), laxAccepts,
		otherErrors, len(entryRefusals), len(binaryRefusals))
	return summary, fails
}
