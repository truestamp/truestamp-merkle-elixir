// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Quotes two error-text fragments, "index is beyond size" and "wrong proof
// size", from github.com/transparency-dev/merkle@v0.0.2 proof/verify.go:59 and
// :67 (Apache-2.0), in oursRefusalReason. License text:
// LICENSE-transparency-dev-merkle; see NOTICE.

package main

// -ours: the truestamp_merkle library's own known answers (vectors/merkle.json,
// written by vectors/generate.exs), held to transparency-dev/merkle v0.0.2 and to
// this program's RFC 9162 reference (ref.go). An entry's leaf data is its
// digest's 32 raw bytes, so its leaf hash is SHA-256(0x00 || digest), and a
// tree's entries are ordered by key, byte-wise ascending.
//
// The sections constants, trees, walk_accepts and walk_refusals must be present
// and non-empty, and every tree with entries must publish paths. Unknown fields
// are ignored, but a field this check reads that is missing or of the wrong JSON
// type is a failure. Only two things are skipped, each counted and named on the
// OK line: an in-scope walk_refusals case whose digest or a path node is a
// string that is not hex, so it has no byte value, and one holding an integer
// outside transparency-dev/merkle's uint64.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// oursLaxAccepts is how many in-scope walk_refusals cases transparency-dev/merkle
// v0.0.2 is allowed to accept. It refuses every one, so any change is a failure.
const oursLaxAccepts = 0

type oursChecker struct {
	errs                                  []string
	trees, emptyTrees, leaves, leafProofs int
	paths, depths                         int
	accepts, acceptsSkipped               int
	refusals, refusalsSkipped, outOfScope int
	laxAccepted                           int
	skipped                               []string
	compactEmpty                          string
}

func (o *oursChecker) fail(format string, args ...any) {
	o.errs = append(o.errs, fmt.Sprintf(format, args...))
}

var jsonInteger = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// u64 reads a JSON integer as a uint64. representable is false for an integer
// outside 0..2^64-1; ok is false for anything that is not a JSON integer.
func u64(raw json.RawMessage) (v uint64, representable, ok bool) {
	s := strings.TrimSpace(string(raw))
	if !jsonInteger.MatchString(s) {
		return 0, false, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil, true
}

func objectOf(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' || json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	return m, true
}

func arrayOf(raw json.RawMessage) ([]json.RawMessage, bool) {
	var a []json.RawMessage
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '[' || json.Unmarshal(raw, &a) != nil {
		return nil, false
	}
	return a, true
}

func stringOf(raw json.RawMessage) (string, bool) {
	var s string
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// hex32 decodes 64 lowercase hex characters.
func hex32(s string) ([]byte, bool) {
	if !hash64.MatchString(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil
}

// hashes32 reads a JSON array of 64-lowercase-hex strings.
func hashes32(raw json.RawMessage) ([][]byte, bool) {
	a, ok := arrayOf(raw)
	if !ok {
		return nil, false
	}
	out := [][]byte{}
	for _, r := range a {
		s, ok := stringOf(r)
		if !ok {
			return nil, false
		}
		b, ok := hex32(s)
		if !ok {
			return nil, false
		}
		out = append(out, b)
	}
	return out, true
}

// Strict field readers for the sections that must be well formed.
func (o *oursChecker) field(where string, m map[string]json.RawMessage, key string) (json.RawMessage, bool) {
	raw, ok := m[key]
	if !ok {
		o.fail("%s: missing %q", where, key)
	}
	return raw, ok
}

func (o *oursChecker) str(where string, m map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := o.field(where, m, key)
	if !ok {
		return "", false
	}
	s, ok := stringOf(raw)
	if !ok {
		o.fail("%s: %q is not a string", where, key)
	}
	return s, ok
}

func (o *oursChecker) hash(where string, m map[string]json.RawMessage, key string) ([]byte, bool) {
	s, ok := o.str(where, m, key)
	if !ok {
		return nil, false
	}
	b, ok := hex32(s)
	if !ok {
		o.fail("%s: %q is not 64 lowercase hex characters", where, key)
	}
	return b, ok
}

func (o *oursChecker) uint(where string, m map[string]json.RawMessage, key string) (uint64, bool) {
	raw, ok := o.field(where, m, key)
	if !ok {
		return 0, false
	}
	v, rep, isInt := u64(raw)
	if !isInt || !rep {
		o.fail("%s: %q is not an integer in 0..2^64-1", where, key)
		return 0, false
	}
	return v, true
}

func (o *oursChecker) array(where string, m map[string]json.RawMessage, key string) ([]json.RawMessage, bool) {
	raw, ok := o.field(where, m, key)
	if !ok {
		return nil, false
	}
	a, ok := arrayOf(raw)
	if !ok {
		o.fail("%s: %q is not an array", where, key)
	}
	return a, ok
}

func (o *oursChecker) object(where string, raw json.RawMessage) (map[string]json.RawMessage, bool) {
	m, ok := objectOf(raw)
	if !ok {
		o.fail("%s: not an object", where)
	}
	return m, ok
}

// section reads a top-level list that must be present and non-empty.
func (o *oursChecker) section(top map[string]json.RawMessage, key string) ([]json.RawMessage, bool) {
	a, ok := o.array("top level", top, key)
	if ok && len(a) == 0 {
		o.fail("top level: section %q is empty", key)
		return nil, false
	}
	return a, ok
}

// anyHex decodes a string of hex digits of either case; ok is false when the
// string has no byte value.
func anyHex(s string) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	return b, err == nil
}

// tdmProofLen is the length of the proof transparency-dev/merkle's own prover
// (proof.Inclusion, then Nodes.Rehash) builds for index in a tree of size.
func tdmProofLen(index, size uint64) (int, error) {
	n, err := proof.Inclusion(index, size)
	if err != nil {
		return 0, err
	}
	hs := make([][]byte, len(n.IDs))
	for i := range hs {
		hs[i] = make([]byte, 32)
	}
	p, err := n.Rehash(hs, rfc6962.DefaultHasher.HashChildren)
	return len(p), err
}

// uncheckedChain runs the RFC 9162 section 2.1.3.2 loop with none of its
// checks (no m < n test, no stop when sn reaches 0, no final sn == 0 test), so
// it yields the root a path would reach if its length were never looked at.
func uncheckedChain(leaf []byte, m, n uint64, path [][]byte) []byte {
	fn, sn := m, n
	if sn > 0 {
		sn--
	}
	r := leaf
	for _, p := range path {
		if fn&1 == 1 || fn == sn {
			r = refNode(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = refNode(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return r
}

// bitChain combines path element i on the left when bit i of the index is set,
// ignoring the tree size.
func bitChain(leaf []byte, m uint64, path [][]byte) []byte {
	r := leaf
	for i, p := range path {
		if i < 64 && (m>>uint(i))&1 == 1 {
			r = refNode(p, r)
		} else {
			r = refNode(r, p)
		}
	}
	return r
}

func (o *oursChecker) check(raw []byte) {
	h := rfc6962.DefaultHasher
	top, ok := objectOf(raw)
	if !ok {
		o.fail("the file is not a JSON object")
		return
	}

	// constants
	var emptyRoot []byte
	if c, ok := o.field("top level", top, "constants"); ok {
		if m, ok := objectOf(c); !ok {
			o.fail("top level: \"constants\" is not an object")
		} else {
			if len(m) == 0 {
				o.fail("top level: section \"constants\" is empty")
			}
			if er, ok := o.hash("constants", m, "empty_root"); ok {
				emptyRoot = er
				if !bytes.Equal(er, h.EmptyRoot()) || !bytes.Equal(er, refEmpty()) {
					o.fail("constants: empty_root %x is not rfc6962 EmptyRoot / SHA-256 of the empty string", er)
				}
			}
			maxSize, okSize := o.uint("constants", m, "max_tree_size")
			if okSize && maxSize != math.MaxUint64 {
				o.fail("constants: max_tree_size %d is not 2^64-1, the largest size transparency-dev/merkle's uint64 API takes", maxSize)
			}
			if ms, ok := o.uint("constants", m, "max_steps"); ok && okSize {
				n, err := tdmProofLen(0, maxSize)
				if err != nil || uint64(n) != ms {
					o.fail("constants: max_steps %d, but transparency-dev/merkle's prover gives a %d-element proof for index 0 of size %d (%v)", ms, n, maxSize, err)
				}
			}
		}
	}

	// trees
	rf := compact.RangeFactory{Hash: h.HashChildren}
	if r, err := rf.NewEmptyRange(0).GetRootHash(nil); r == nil && err == nil {
		o.compactEmpty = "compact.Range has no empty-tree root (GetRootHash returns nil); rfc6962 EmptyRoot and testonly.Tree give it"
	} else {
		o.compactEmpty = fmt.Sprintf("compact.Range gives an empty-tree root %x (%v)", r, err)
	}
	if ta, ok := o.section(top, "trees"); ok {
		for ti, traw := range ta {
			o.checkTree(fmt.Sprintf("trees[%d]", ti), traw, emptyRoot)
		}
	}

	// walk_accepts
	if wa, ok := o.section(top, "walk_accepts"); ok {
		for i, raw := range wa {
			o.checkAccept(fmt.Sprintf("walk_accepts[%d]", i), raw)
		}
	}

	// walk_refusals
	if wr, ok := o.section(top, "walk_refusals"); ok {
		for i, raw := range wr {
			o.checkRefusal(fmt.Sprintf("walk_refusals[%d]", i), raw)
		}
		if o.refusals == o.refusalsSkipped {
			o.fail("walk_refusals: no in-scope case (index_out_of_range or wrong_path_length) could be checked")
		}
	}
	if o.laxAccepted != oursLaxAccepts {
		o.fail("transparency-dev/merkle accepted %d in-scope walk_refusals cases; the pinned count is %d", o.laxAccepted, oursLaxAccepts)
	}
}

func (o *oursChecker) checkTree(where string, raw json.RawMessage, emptyRoot []byte) {
	h := rfc6962.DefaultHasher
	t, ok := o.object(where, raw)
	if !ok {
		return
	}
	name, ok := o.str(where, t, "name")
	if !ok {
		return
	}
	where = fmt.Sprintf("tree %q", name)
	o.trees++
	ea, ok1 := o.array(where, t, "entries")
	root, ok2 := o.hash(where, t, "root")
	size, ok3 := o.uint(where, t, "tree_size")
	pa, ok4 := o.array(where, t, "paths")
	depth, ok5 := o.uint(where, t, "depth")
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return
	}
	if len(ea) > 0 && len(pa) == 0 {
		o.fail("%s: the tree has entries but its paths list is empty", where)
	}
	type entry struct {
		key    string
		digest []byte
	}
	var es []entry
	keys := map[string]bool{}
	for i, er := range ea {
		w := fmt.Sprintf("%s entries[%d]", where, i)
		m, ok := o.object(w, er)
		if !ok {
			return
		}
		k, ok1 := o.str(w, m, "key")
		d, ok2 := o.hash(w, m, "digest")
		if !ok1 || !ok2 {
			return
		}
		if keys[k] {
			o.fail("%s: key %q repeats", w, k)
			return
		}
		keys[k] = true
		es = append(es, entry{k, d})
	}
	sort.SliceStable(es, func(i, j int) bool { return es[i].key < es[j].key })
	if uint64(len(es)) != size {
		o.fail("%s: %d entries for tree_size %d", where, len(es), size)
		return
	}
	lh := make([][]byte, len(es))
	pos := map[string]int{}
	for i, e := range es {
		lh[i] = h.HashLeaf(e.digest)
		if !bytes.Equal(lh[i], refLeaf(e.digest)) {
			o.fail("%s: rfc6962 HashLeaf disagrees with the RFC reference for %q", where, e.key)
		}
		pos[e.key] = i
	}
	o.leaves += len(lh)

	// (a) the root, three ways: compact.Range (rfc6962 EmptyRoot when empty),
	// testonly.Tree, and the RFC reference.
	tt := testonly.New(h)
	tt.Append(lh...)
	switch {
	case !bytes.Equal(tdmRoot(lh), root):
		o.fail("%s: root %x, transparency-dev/merkle compact.Range gives %x", where, root, tdmRoot(lh))
	case !bytes.Equal(tt.Hash(), root):
		o.fail("%s: root %x, transparency-dev/merkle testonly.Tree gives %x", where, root, tt.Hash())
	case !bytes.Equal(refMTH(lh), root):
		o.fail("%s: root %x, the RFC reference gives %x", where, root, refMTH(lh))
	}
	if len(lh) == 0 {
		o.emptyTrees++
		if emptyRoot != nil && !bytes.Equal(root, emptyRoot) {
			o.fail("%s: the empty tree's root is not constants.empty_root", where)
		}
	}
	// every leaf proves against the root with transparency-dev/merkle's own
	// prover, and depth is the longest of those proofs (0 with no leaves)
	var longest, refLongest int
	for m := range lh {
		p, err := tt.InclusionProof(uint64(m), size)
		if err != nil || proof.VerifyInclusion(h, uint64(m), size, lh[m], p, root) != nil {
			o.fail("%s: transparency-dev/merkle's own proof for leaf %d does not verify%s", where, m, errNote(err))
		}
		longest = max(longest, len(p))
		refLongest = max(refLongest, len(refPath(uint64(m), lh)))
		o.leafProofs++
	}
	switch {
	case depth != uint64(longest):
		o.fail("%s: depth %d, but the longest transparency-dev/merkle testonly.Tree.InclusionProof has %d nodes", where, depth, longest)
	case depth != uint64(refLongest):
		o.fail("%s: depth %d, but the longest RFC reference PATH(m, D[n]) has %d nodes", where, depth, refLongest)
	default:
		o.depths++
	}

	// (b) every published path
	for i, praw := range pa {
		w := fmt.Sprintf("%s paths[%d]", where, i)
		pm, ok := o.object(w, praw)
		if !ok {
			continue
		}
		key, ok1 := o.str(w, pm, "key")
		dg, ok2 := o.hash(w, pm, "digest")
		idx, ok3 := o.uint(w, pm, "leaf_index")
		psize, ok4 := o.uint(w, pm, "tree_size")
		prawp, ok5 := o.field(w, pm, "path")
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
			continue
		}
		path, ok := hashes32(prawp)
		if !ok {
			o.fail("%s: path is not an array of 64-character lowercase hex strings", w)
			continue
		}
		o.paths++
		at, found := pos[key]
		switch {
		case !found:
			o.fail("%s: key %q is not an entry", w, key)
			continue
		case !bytes.Equal(dg, es[at].digest):
			o.fail("%s: digest is not the entry's", w)
			continue
		case idx != uint64(at):
			o.fail("%s: leaf_index %d, but %q sorts to position %d", w, idx, key, at)
			continue
		case psize != size:
			o.fail("%s: tree_size %d, the tree has %d", w, psize, size)
			continue
		}
		leaf := h.HashLeaf(dg)
		if err := proof.VerifyInclusion(h, idx, psize, leaf, path, root); err != nil {
			o.fail("%s: transparency-dev/merkle rejects the path: %v", w, err)
		}
		if !refVerify(leaf, idx, psize, path, root) {
			o.fail("%s: the RFC reference rejects the path", w)
		}
		own, err := tt.InclusionProof(idx, psize)
		if err != nil || !equalHashes(own, path) {
			o.fail("%s: the path is not transparency-dev/merkle's own proof (testonly.Tree.InclusionProof)%s", w, errNote(err))
		}
		if !equalHashes(refPath(idx, lh), path) {
			o.fail("%s: the path is not the RFC reference's PATH(m, D[n])", w)
		}
	}
}

func errNote(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

func equalHashes(a, b [][]byte) bool {
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

func (o *oursChecker) checkAccept(where string, raw json.RawMessage) {
	h := rfc6962.DefaultHasher
	m, ok := o.object(where, raw)
	if !ok {
		return
	}
	name, ok := o.str(where, m, "name")
	if !ok {
		return
	}
	where = fmt.Sprintf("walk_accepts %q", name)
	dg, ok1 := o.hash(where, m, "digest")
	root, ok2 := o.hash(where, m, "root")
	praw, ok3 := o.field(where, m, "proof")
	if !ok1 || !ok2 || !ok3 {
		return
	}
	pm, ok := o.object(where+" proof", praw)
	if !ok {
		return
	}
	iraw, ok1 := o.field(where+" proof", pm, "leaf_index")
	sraw, ok2 := o.field(where+" proof", pm, "tree_size")
	pathRaw, ok3 := o.field(where+" proof", pm, "path")
	if !ok1 || !ok2 || !ok3 {
		return
	}
	idx, repI, intI := u64(iraw)
	size, repS, intS := u64(sraw)
	if !intI || !intS {
		o.fail("%s: leaf_index or tree_size is not a JSON integer", where)
		return
	}
	path, ok := hashes32(pathRaw)
	if !ok {
		o.fail("%s: path is not an array of 64-character lowercase hex strings", where)
		return
	}
	o.accepts++
	if !repI || !repS {
		o.acceptsSkipped++
		o.skipped = append(o.skipped, fmt.Sprintf("walk_accepts %q (an integer outside uint64)", name))
		return
	}
	leaf := h.HashLeaf(dg)
	got, err := proof.RootFromInclusionProof(h, idx, size, leaf, path)
	if err != nil || !bytes.Equal(got, root) || proof.VerifyInclusion(h, idx, size, leaf, path, root) != nil {
		o.fail("%s: transparency-dev/merkle does not reach the root%s", where, errNote(err))
	}
	if !refVerify(leaf, idx, size, path, root) {
		o.fail("%s: the RFC reference rejects it", where)
	}
}

// oursRefusalReason maps an in-scope error to the transparency-dev/merkle v0.0.2
// error text for the same refusal, quoted from proof/verify.go:59 and :67
// (RootFromInclusionProof).
var oursRefusalReason = map[string]string{
	"index_out_of_range": "index is beyond size",
	"wrong_path_length":  "wrong proof size",
}

func (o *oursChecker) checkRefusal(where string, raw json.RawMessage) {
	h := rfc6962.DefaultHasher
	m, ok := o.object(where, raw)
	if !ok {
		return
	}
	name, ok1 := o.str(where, m, "name")
	errName, ok2 := o.str(where, m, "error")
	if !ok1 || !ok2 {
		return
	}
	where = fmt.Sprintf("walk_refusals %q", name)
	reason, inScope := oursRefusalReason[errName]
	if !inScope {
		o.outOfScope++
		return
	}
	o.refusals++

	// Every field is required and must have its JSON type; a missing or
	// mistyped field is a failure, never a skip.
	dgs, ok1 := o.str(where, m, "digest")
	praw, ok2 := o.field(where, m, "proof")
	if !ok1 || !ok2 {
		return
	}
	pm, ok := o.object(where+" proof", praw)
	if !ok {
		return
	}
	iraw, ok1 := o.field(where+" proof", pm, "leaf_index")
	sraw, ok2 := o.field(where+" proof", pm, "tree_size")
	pa, ok3 := o.array(where+" proof", pm, "path")
	if !ok1 || !ok2 || !ok3 {
		return
	}
	idx, repI, intI := u64(iraw)
	size, repS, intS := u64(sraw)
	if !intI || !intS {
		o.fail("%s: leaf_index or tree_size is not a JSON integer", where)
		return
	}
	nodes := make([]string, len(pa))
	for i, r := range pa {
		s, ok := stringOf(r)
		if !ok {
			o.fail("%s: path[%d] is not a string", where, i)
			return
		}
		nodes[i] = s
	}

	// The two allowed skips: a string with no byte value, and an integer
	// outside transparency-dev/merkle's uint64.
	var why []string
	dg, ok := anyHex(dgs)
	if !ok {
		why = append(why, "the digest is not hex, so it has no byte value")
	}
	path := make([][]byte, len(nodes))
	for i, s := range nodes {
		b, ok := anyHex(s)
		if !ok {
			why = append(why, fmt.Sprintf("path[%d] %q is not hex, so it has no byte value", i, s))
		}
		path[i] = b
	}
	if !repI || !repS {
		why = append(why, "leaf_index or tree_size is outside transparency-dev/merkle's uint64")
	}
	if len(why) > 0 {
		o.refusalsSkipped++
		o.skipped = append(o.skipped, fmt.Sprintf("walk_refusals %q (%s)", name, strings.Join(why, "; ")))
		return
	}

	leaf := h.HashLeaf(dg)
	accepted := false
	_, err := proof.RootFromInclusionProof(h, idx, size, leaf, path)
	switch {
	case err == nil:
		accepted = true
		o.fail("%s: transparency-dev/merkle computes a root, where the vector says %s", where, errName)
	case !strings.Contains(err.Error(), reason):
		o.fail("%s: the vector says %s, transparency-dev/merkle refuses with %q", where, errName, err)
	}
	// The root a length-blind chain would reach, two ways: neither may verify.
	for _, root := range [][]byte{uncheckedChain(leaf, idx, size, path), bitChain(leaf, idx, path)} {
		if proof.VerifyInclusion(h, idx, size, leaf, path, root) == nil {
			accepted = true
			o.fail("%s: transparency-dev/merkle accepts it against root %x", where, root)
		}
		if refVerify(leaf, idx, size, path, root) {
			o.fail("%s: the RFC reference accepts it against root %x", where, root)
		}
	}
	if accepted {
		o.laxAccepted++
	}
}

// checkOurs runs the -ours check and returns the lines to print.
func checkOurs(raw []byte) (lines []string, ok bool) {
	o := &oursChecker{}
	o.check(raw)
	if len(o.errs) > 0 {
		for _, e := range o.errs {
			lines = append(lines, "FAIL ours "+oneLine(e))
		}
		return lines, false
	}
	skipped := "none"
	if len(o.skipped) > 0 {
		skipped = strings.Join(o.skipped, "; ")
	}
	return []string{fmt.Sprintf("OK ours %s: transparency-dev/merkle v0.0.2 + RFC 9162 reference: constants (empty_root, max_tree_size, max_steps), %d trees (%d empty; %d leaves; roots by compact.Range, testonly.Tree and the RFC reference; %s; %d depths equal the longest testonly.Tree.InclusionProof and RFC PATH), %d leaf proofs by transparency-dev/merkle's prover, %d published paths (verify; equal testonly.Tree.InclusionProof and the RFC PATH), %d walk_accepts (%d verified, %d skipped), %d in-scope walk_refusals (%d refused with the named reason, %d skipped; %d accepted, pinned %d), %d walk_refusals out of scope; %d skipped: %s",
		label(version), o.trees, o.emptyTrees, o.leaves, o.compactEmpty, o.depths, o.leafProofs, o.paths, o.accepts, o.accepts-o.acceptsSkipped, o.acceptsSkipped,
		o.refusals, o.refusals-o.refusalsSkipped, o.refusalsSkipped, o.laxAccepted, oursLaxAccepts, o.outOfScope, len(o.skipped), skipped)}, true
}
