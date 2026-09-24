// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Quotes two error-message prefixes, "index is beyond size" and "wrong proof
// size", from github.com/transparency-dev/merkle@v0.0.2 (Apache-2.0,
// Copyright Google LLC) proof/verify.go:59 and :67. The upstream license is
// vendored as LICENSE-transparency-dev-merkle; see NOTICE.

package main

// The -ours mode: truestamp_merkle's own known answers (vectors/merkle.json,
// written by vectors/generate.exs) checked with this implementation's
// functions. An entry's leaf data is its digest's 32 raw bytes, and a tree's
// entries are ordered by key, byte-wise ascending.
//
// The file is read member by member. The sections constants, trees,
// walk_accepts and walk_refusals must be present and non-empty, and every
// member a check uses must be present with the right JSON type; anything else
// is a FAIL. Members this program does not use (binary_hex, max_steps of a
// walk case, entry_refusals, binary_refusals, and any new field) are ignored.
// The only skips are the two the implementation's API forces: a walk case
// integer outside 0..2^64-1 (uint64 cannot hold it) and a walk_refusals path
// node that is not hex ([][]byte has no value for it). Both skip counts are
// pinned below, like the lax-accept count.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// oursLaxAccepts is the number of walk_refusals cases (index_out_of_range or
// wrong_path_length, with fields this API can represent) that the
// implementation accepts. transparency-dev/merkle is strict: it refuses every
// one, so the constant is 0 and any acceptance fails the run.
const oursLaxAccepts = 0

// oursAcceptSkips and oursRefusalSkips are the expected skip counts for
// vectors/merkle.json: no walk_accepts integer falls outside uint64 (the
// largest tree_size is 2^64-1), and one in-scope walk_refusals case, "the
// path length is checked before any node", has the non-hex path node "bad".
// A different count fails the run, so a case that becomes unrepresentable is
// reported rather than quietly skipped.
const (
	oursAcceptSkips  = 0
	oursRefusalSkips = 1
)

// oursRefusalReason maps a walk_refusals error name to the start of the error
// proof.RootFromInclusionProof returns for it (proof/verify.go:59 and :67 at
// v0.0.2).
var oursRefusalReason = map[string]string{
	"index_out_of_range": "index is beyond size",
	"wrong_path_length":  "wrong proof size",
}

// jsonObject is a JSON object read member by member.
type jsonObject map[string]json.RawMessage

type oursChecker struct {
	errs []string

	trees, emptyTrees, leaves  int
	testonlyRoots, rangeRoots  int
	depths, paths              int
	accepts                    int
	acceptsSkipped             []string
	refusalsChecked            int
	refusalsSkipped            []string
	refusalsOther              int
	laxAccepted                []string
	candidateRootsPerRefusal   int
	constantsChecked           int
	maxStepsFromImplementation int
}

func (o *oursChecker) fail(format string, args ...any) {
	o.errs = append(o.errs, oneLine(fmt.Sprintf(format, args...)))
}

// guard runs one part of the -ours check, turning a panic into a FAIL line.
func (o *oursChecker) guard(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			o.fail("%s: panic: %v", what, r)
		}
	}()
	fn()
}

// absent reports whether a member is missing or null.
func absent(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// excerpt shortens a raw JSON value for a FAIL line.
func excerpt(raw json.RawMessage) string {
	t := strings.TrimSpace(string(raw))
	if len(t) > 40 {
		t = t[:40] + "..."
	}
	return t
}

func (o *oursChecker) object(what string, raw json.RawMessage) (jsonObject, bool) {
	if absent(raw) {
		o.fail("%s: missing", what)
		return nil, false
	}
	var m jsonObject
	if err := json.Unmarshal(raw, &m); err != nil {
		o.fail("%s: %s is not a JSON object", what, excerpt(raw))
		return nil, false
	}
	return m, true
}

func (o *oursChecker) list(what string, raw json.RawMessage) ([]json.RawMessage, bool) {
	if absent(raw) {
		o.fail("%s: missing", what)
		return nil, false
	}
	var l []json.RawMessage
	if err := json.Unmarshal(raw, &l); err != nil {
		o.fail("%s: %s is not a JSON list", what, excerpt(raw))
		return nil, false
	}
	return l, true
}

func (o *oursChecker) str(what string, raw json.RawMessage) (string, bool) {
	if absent(raw) {
		o.fail("%s: missing", what)
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		o.fail("%s: %s is not a JSON string", what, excerpt(raw))
		return "", false
	}
	return s, true
}

// intKind classifies a JSON value read as an unsigned 64-bit integer.
type intKind int

const (
	intOK         intKind = iota
	intMissing            // absent or null
	intNotInteger         // another JSON type, or a number with a fraction or exponent
	intOutOfRange         // a JSON integer outside 0..2^64-1
)

var jsonIntegerRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// jsonUint parses a JSON integer in 0..2^64-1; why says what is wrong
// otherwise.
func jsonUint(raw json.RawMessage) (n uint64, kind intKind, why string) {
	if absent(raw) {
		return 0, intMissing, "missing"
	}
	t := strings.TrimSpace(string(raw))
	if !jsonIntegerRE.MatchString(t) {
		return 0, intNotInteger, excerpt(raw) + " is not a JSON integer"
	}
	n, err := strconv.ParseUint(t, 10, 64)
	if err != nil {
		return 0, intOutOfRange, t + " is outside 0..2^64-1"
	}
	return n, intOK, ""
}

// u64 reads a required integer member in 0..2^64-1.
func (o *oursChecker) u64(what string, raw json.RawMessage) (uint64, bool) {
	n, kind, why := jsonUint(raw)
	if kind != intOK {
		o.fail("%s: %s", what, why)
		return 0, false
	}
	return n, true
}

// digest reads a required member holding a 64-character lowercase hex digest.
func (o *oursChecker) digest(what string, raw json.RawMessage) ([]byte, bool) {
	s, ok := o.str(what, raw)
	if !ok {
		return nil, false
	}
	return o.hexDigest(what, s)
}

func (o *oursChecker) hexDigest(what, s string) ([]byte, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 || s != strings.ToLower(s) {
		o.fail("%s: %q is not 64 lowercase hex characters", what, s)
		return nil, false
	}
	return b, true
}

// proofProblem classifies why decodeProof could not produce API arguments.
type proofProblem int

const (
	proofOK        proofProblem = iota
	proofMalformed              // missing, not an object, a member missing or of the wrong JSON type: a FAIL
	proofInteger                // an integer outside 0..2^64-1: this API's uint64 cannot take it (a skip)
	proofNode                   // a path node that is not hex: this API's [][]byte has no value for it (a skip)
)

// decodeProof reads a walk case's proof object into the API's arguments.
// nodes holds the path's strings, path their bytes. When several members are
// wrong, a malformed one wins over an unrepresentable one, so a skip never
// hides a defect.
func decodeProof(raw json.RawMessage) (index, size uint64, nodes []string, path [][]byte, why string, problem proofProblem) {
	if absent(raw) {
		return 0, 0, nil, nil, "proof missing", proofMalformed
	}
	var m jsonObject
	if json.Unmarshal(raw, &m) != nil {
		return 0, 0, nil, nil, "proof " + excerpt(raw) + " is not a JSON object", proofMalformed
	}
	var skipWhy string
	integer := func(member string) (uint64, bool) {
		n, kind, w := jsonUint(m[member])
		switch kind {
		case intOK:
			return n, true
		case intOutOfRange:
			if skipWhy == "" {
				skipWhy = "proof." + member + " " + w
			}
		default:
			if why == "" {
				why = "proof." + member + " " + w
			}
		}
		return 0, false
	}
	index, _ = integer("leaf_index")
	size, _ = integer("tree_size")
	if why != "" {
		return 0, 0, nil, nil, why, proofMalformed
	}
	p := m["path"]
	if absent(p) {
		return 0, 0, nil, nil, "proof.path missing", proofMalformed
	}
	var items []json.RawMessage
	if json.Unmarshal(p, &items) != nil {
		return 0, 0, nil, nil, "proof.path " + excerpt(p) + " is not a JSON list", proofMalformed
	}
	nodes = make([]string, len(items))
	for i, it := range items {
		if absent(it) || json.Unmarshal(it, &nodes[i]) != nil {
			return 0, 0, nil, nil, fmt.Sprintf("proof.path[%d] %s is not a JSON string", i, excerpt(it)), proofMalformed
		}
	}
	if skipWhy != "" {
		return 0, 0, nil, nil, skipWhy, proofInteger
	}
	path = make([][]byte, len(nodes))
	for i, s := range nodes {
		b, err := hex.DecodeString(s)
		if err != nil {
			return 0, 0, nil, nil, fmt.Sprintf("proof.path[%d] %q is not hex", i, s), proofNode
		}
		path[i] = b
	}
	return index, size, nodes, path, "", proofOK
}

// uncheckedChain is RFC 9162 section 2.1.3.2 steps 2 to 4 with every check
// removed (step 1's index test, step 4a's early stop, step 5's sn == 0): the
// root a verifier that trusted the path's length would reach.
func uncheckedChain(leafHash []byte, index, size uint64, path [][]byte) []byte {
	fn, sn := index, uint64(0)
	if size > 0 {
		sn = size - 1
	}
	r := leafHash
	for _, p := range path {
		if fn&1 == 1 || fn == sn {
			r = ih.HashChildren(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = ih.HashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return r
}

// indexBitChain folds the path by the bits of the index alone (bit i set: the
// node is on the left), ignoring the tree size: the classic unchecked chain.
func indexBitChain(leafHash []byte, index uint64, path [][]byte) []byte {
	r := leafHash
	for i, p := range path {
		if i < 64 && (index>>uint(i))&1 == 1 {
			r = ih.HashChildren(p, r)
		} else {
			r = ih.HashChildren(r, p)
		}
	}
	return r
}

// namesOrNone joins skipped-case descriptions for the OK line.
func namesOrNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, "; ")
}

// checkOurs runs every check of the -ours mode and returns the summary.
func checkOurs(path string) (summary string, errs []string) {
	o := &oursChecker{}
	defer func() {
		if r := recover(); r != nil {
			o.fail("panic: %v", r)
			summary, errs = "", o.errs
		}
	}()
	raw, err := os.ReadFile(path)
	if err != nil {
		o.fail("read %s: %v", path, err)
		return "", o.errs
	}
	var top jsonObject
	if err := json.Unmarshal(raw, &top); err != nil {
		o.fail("parse %s: %v", path, err)
		return "", o.errs
	}

	o.guard("constants", func() { o.checkConstants(top["constants"]) })
	for _, s := range []struct {
		name  string
		check func([]json.RawMessage)
	}{
		{"trees", o.checkTrees},
		{"walk_accepts", o.checkAccepts},
		{"walk_refusals", o.checkRefusals},
	} {
		cases, ok := o.list(s.name, top[s.name])
		if !ok {
			continue
		}
		if len(cases) == 0 {
			o.fail("%s: empty list", s.name)
			continue
		}
		o.guard(s.name, func() { s.check(cases) })
	}

	summary = fmt.Sprintf("constants %d/3 (empty_root is rfc6962 EmptyRoot and testonly.Tree.HashAt(0); max_tree_size is the largest uint64 size; the audit path for leaf 0 of max_tree_size, by proof.Inclusion and Nodes.Rehash, has max_steps = %d nodes); "+
		"%d trees (%d empty, %d leaves): %d roots by testonly.Tree, %d by compact.Range (it has no empty-tree root: GetRootHash returns nil), %d depths equal the longest testonly.Tree.InclusionProof; "+
		"%d paths verified by proof.VerifyInclusion and proof.RootFromInclusionProof and equal to testonly.Tree.InclusionProof; "+
		"walk_accepts %d verified by proof.VerifyInclusion and proof.RootFromInclusionProof, %d skipped (pinned %d): %s; the implementation has no step cap, so max_steps is not applied; "+
		"walk_refusals %d index_out_of_range/wrong_path_length refused by proof.RootFromInclusionProof with the named reason and by proof.VerifyInclusion against %d candidate roots each (lax accepts %d, pinned %d), %d skipped (pinned %d): %s; %d cases of other kinds not applicable; "+
		"entry_refusals and binary_refusals not applicable (library key rules and binary encoding)",
		o.constantsChecked, o.maxStepsFromImplementation,
		o.trees, o.emptyTrees, o.leaves, o.testonlyRoots, o.rangeRoots, o.depths,
		o.paths,
		o.accepts, len(o.acceptsSkipped), oursAcceptSkips, namesOrNone(o.acceptsSkipped),
		o.refusalsChecked, o.candidateRootsPerRefusal, len(o.laxAccepted), oursLaxAccepts, len(o.refusalsSkipped), oursRefusalSkips, namesOrNone(o.refusalsSkipped), o.refusalsOther)
	return summary, o.errs
}

func (o *oursChecker) checkConstants(raw json.RawMessage) {
	h := rfc6962.DefaultHasher
	k, ok := o.object("constants", raw)
	if !ok {
		return
	}
	if len(k) == 0 {
		o.fail("constants: empty object")
		return
	}
	if er, ok := o.digest("constants.empty_root", k["empty_root"]); ok {
		if !bytes.Equal(er, h.EmptyRoot()) || !bytes.Equal(er, testonly.New(h).HashAt(0)) {
			o.fail("constants.empty_root %x: rfc6962 EmptyRoot %x, testonly.Tree.HashAt(0) %x", er, h.EmptyRoot(), testonly.New(h).HashAt(0))
		} else {
			o.constantsChecked++
		}
	}
	maxSize, okSize := o.u64("constants.max_tree_size", k["max_tree_size"])
	maxSteps, okSteps := o.u64("constants.max_steps", k["max_steps"])
	if !okSize {
		return
	}
	if maxSize != math.MaxUint64 {
		o.fail("constants.max_tree_size %d, the implementation's sizes are uint64 (largest %d)", maxSize, uint64(math.MaxUint64))
		return
	}
	o.constantsChecked++
	// The audit path for leaf 0 of the largest tree: proof.Inclusion gives its
	// node IDs (the right border as separate perfect subtrees), and
	// Nodes.Rehash folds those into the ephemeral node, as the prover does.
	nodes, err := proof.Inclusion(0, maxSize)
	if err != nil {
		o.fail("proof.Inclusion(0, %d): %v", maxSize, err)
		return
	}
	stand := make([][]byte, len(nodes.IDs))
	for i := range stand {
		stand[i] = h.EmptyRoot()
	}
	path, err := nodes.Rehash(stand, h.HashChildren)
	if err != nil {
		o.fail("proof.Nodes.Rehash for (0, %d): %v", maxSize, err)
		return
	}
	o.maxStepsFromImplementation = len(path)
	if !okSteps {
		return
	}
	if uint64(len(path)) != maxSteps {
		o.fail("constants.max_steps %d, the implementation's audit path for leaf 0 of max_tree_size has %d nodes", maxSteps, len(path))
	} else {
		o.constantsChecked++
	}
}

func (o *oursChecker) checkTrees(trees []json.RawMessage) {
	h := rfc6962.DefaultHasher
	factory := &compact.RangeFactory{Hash: h.HashChildren}
	names := map[string]bool{}
	for ti, traw := range trees {
		o.trees++
		what := fmt.Sprintf("trees[%d]", ti)
		t, ok := o.object(what, traw)
		if !ok {
			continue
		}
		name, ok := o.str(what+" name", t["name"])
		if !ok {
			continue
		}
		if name == "" {
			o.fail("%s: name is empty", what)
			continue
		}
		if names[name] {
			o.fail("tree %q: duplicate name", name)
		}
		names[name] = true
		what = fmt.Sprintf("tree %q", name)
		root, okRoot := o.digest(what+" root", t["root"])
		entries, okEntries := o.list(what+" entries", t["entries"])
		treeSize, okSize := o.u64(what+" tree_size", t["tree_size"])
		depth, okDepth := o.u64(what+" depth", t["depth"])
		paths, okPaths := o.list(what+" paths", t["paths"])
		if !okRoot || !okEntries || !okSize || !okDepth || !okPaths {
			continue
		}
		if len(entries) > 0 && len(paths) == 0 {
			o.fail("%s: paths is empty for a tree of %d entries", what, len(entries))
			continue
		}

		type leaf struct {
			key    string
			digest []byte
		}
		leaves := make([]leaf, 0, len(entries))
		good := true
		for i, eraw := range entries {
			ew := fmt.Sprintf("%s entries[%d]", what, i)
			e, ok := o.object(ew, eraw)
			if !ok {
				good = false
				continue
			}
			key, okKey := o.str(ew+" key", e["key"])
			d, okDigest := o.digest(ew+" digest", e["digest"])
			if !okKey || !okDigest {
				good = false
				continue
			}
			leaves = append(leaves, leaf{key, d})
		}
		if !good {
			continue
		}
		sort.SliceStable(leaves, func(i, j int) bool { return leaves[i].key < leaves[j].key })
		index := map[string]uint64{}
		for i, l := range leaves {
			if _, dup := index[l.key]; dup {
				o.fail("%s: key %q appears twice", what, l.key)
				good = false
			}
			index[l.key] = uint64(i)
		}
		if !good {
			continue
		}
		n := uint64(len(leaves))
		if treeSize != n {
			o.fail("%s: tree_size %d, %d entries", what, treeSize, n)
			continue
		}
		o.leaves += int(n)

		// Root by the implementation's tree builder over the digests as leaf
		// data (testonly.Tree hashes each with rfc6962 HashLeaf), and by
		// compact.Range over the same leaf hashes.
		tree := testonly.New(h)
		rng := factory.NewEmptyRange(0)
		for _, l := range leaves {
			tree.AppendData(l.digest)
			if err := rng.Append(h.HashLeaf(l.digest), nil); err != nil {
				o.fail("%s: compact.Range Append: %v", what, err)
			}
		}
		if got := tree.Hash(); !bytes.Equal(got, root) {
			o.fail("%s: testonly.Tree root %x, vectors %x", what, got, root)
		} else {
			o.testonlyRoots++
		}
		cr, err := rng.GetRootHash(nil)
		switch {
		case err != nil:
			o.fail("%s: compact.Range GetRootHash: %v", what, err)
		case n == 0:
			o.emptyTrees++
			if cr != nil {
				o.fail("%s: compact.Range root of an empty range is %x, expected nil (upstream behaviour)", what, cr)
			}
			if !bytes.Equal(root, h.EmptyRoot()) {
				o.fail("%s: empty tree root %x, rfc6962 EmptyRoot %x", what, root, h.EmptyRoot())
			}
		case !bytes.Equal(cr, root):
			o.fail("%s: compact.Range root %x, vectors %x", what, cr, root)
		default:
			o.rangeRoots++
		}

		// depth: the longest audit path the implementation's prover gives.
		var longest uint64
		for i := uint64(0); i < n; i++ {
			p, err := tree.InclusionProof(i, n)
			if err != nil {
				o.fail("%s: testonly.Tree.InclusionProof(%d, %d): %v", what, i, n, err)
				break
			}
			if uint64(len(p)) > longest {
				longest = uint64(len(p))
			}
		}
		if depth != longest {
			o.fail("%s: depth %d, longest testonly.Tree.InclusionProof has %d nodes", what, depth, longest)
		} else {
			o.depths++
		}

		for pi, praw := range paths {
			pw := fmt.Sprintf("%s paths[%d]", what, pi)
			p, ok := o.object(pw, praw)
			if !ok {
				continue
			}
			key, okKey := o.str(pw+" key", p["key"])
			d, okDigest := o.digest(pw+" digest", p["digest"])
			leafIndex, okIndex := o.u64(pw+" leaf_index", p["leaf_index"])
			pathSize, okPathSize := o.u64(pw+" tree_size", p["tree_size"])
			items, okPath := o.list(pw+" path", p["path"])
			if !okKey || !okDigest || !okIndex || !okPathSize || !okPath {
				continue
			}
			nodes := make([][]byte, len(items))
			nodesOK := true
			for j, it := range items {
				b, ok := o.digest(fmt.Sprintf("%s path[%d]", pw, j), it)
				nodesOK = nodesOK && ok
				nodes[j] = b
			}
			if !nodesOK {
				continue
			}
			pw = fmt.Sprintf("%s path for key %q", what, key)
			i, ok := index[key]
			if !ok {
				o.fail("%s: no such entry", pw)
				continue
			}
			if leafIndex != i || pathSize != n || !bytes.Equal(d, leaves[i].digest) {
				o.fail("%s: leaf_index %d, tree_size %d, digest %x; the sorted entries give %d, %d, %x", pw, leafIndex, pathSize, d, i, n, leaves[i].digest)
				continue
			}
			leafHash := h.HashLeaf(d)
			if err := proof.VerifyInclusion(h, i, n, leafHash, nodes, root); err != nil {
				o.fail("%s: proof.VerifyInclusion: %v", pw, err)
			}
			if got, err := proof.RootFromInclusionProof(h, i, n, leafHash, nodes); err != nil || !bytes.Equal(got, root) {
				o.fail("%s: proof.RootFromInclusionProof %x (%v), root %x", pw, got, err, root)
			}
			if want, err := tree.InclusionProof(i, n); err != nil || !pathsEqual(want, nodes) {
				o.fail("%s: testonly.Tree.InclusionProof %x (%v) differs from the vectors' path", pw, want, err)
			}
			o.paths++
		}
	}
}

func (o *oursChecker) checkAccepts(cases []json.RawMessage) {
	h := rfc6962.DefaultHasher
	for ci, raw := range cases {
		what := fmt.Sprintf("walk_accepts[%d]", ci)
		c, ok := o.object(what, raw)
		if !ok {
			continue
		}
		name, ok := o.str(what+" name", c["name"])
		if !ok {
			continue
		}
		what = fmt.Sprintf("walk_accepts[%d] %q", ci, name)
		d, okDigest := o.digest(what+" digest", c["digest"])
		root, okRoot := o.digest(what+" root", c["root"])
		index, size, nodes, path, why, problem := decodeProof(c["proof"])
		if !okDigest || !okRoot {
			continue
		}
		switch problem {
		case proofOK:
		case proofInteger:
			o.acceptsSkipped = append(o.acceptsSkipped, fmt.Sprintf("%q (%s)", name, why))
			continue
		default:
			// A case the library accepts has well-formed hex nodes, so a
			// non-hex node here is a defect in the file, not a skip.
			o.fail("%s: %s", what, why)
			continue
		}
		nodesOK := true
		for j, s := range nodes {
			_, ok := o.hexDigest(fmt.Sprintf("%s proof.path[%d]", what, j), s)
			nodesOK = nodesOK && ok
		}
		if !nodesOK {
			continue
		}
		leafHash := h.HashLeaf(d)
		if err := proof.VerifyInclusion(h, index, size, leafHash, path, root); err != nil {
			o.fail("%s: proof.VerifyInclusion: %v", what, err)
			continue
		}
		if got, err := proof.RootFromInclusionProof(h, index, size, leafHash, path); err != nil || !bytes.Equal(got, root) {
			o.fail("%s: proof.RootFromInclusionProof %x (%v), root %x", what, got, err, root)
			continue
		}
		o.accepts++
	}
	if len(o.acceptsSkipped) != oursAcceptSkips {
		o.fail("walk_accepts: %d skipped (%s), constant oursAcceptSkips is %d", len(o.acceptsSkipped), namesOrNone(o.acceptsSkipped), oursAcceptSkips)
	}
}

func (o *oursChecker) checkRefusals(cases []json.RawMessage) {
	h := rfc6962.DefaultHasher
	o.candidateRootsPerRefusal = 2
	for ci, raw := range cases {
		what := fmt.Sprintf("walk_refusals[%d]", ci)
		c, ok := o.object(what, raw)
		if !ok {
			continue
		}
		name, ok := o.str(what+" name", c["name"])
		if !ok {
			continue
		}
		what = fmt.Sprintf("walk_refusals[%d] %q", ci, name)
		errName, ok := o.str(what+" error", c["error"])
		if !ok {
			continue
		}
		reason, inScope := oursRefusalReason[errName]
		if !inScope {
			o.refusalsOther++
			continue
		}
		// The library checks the digest first, then the proof's shape, so a
		// case named for a range or length error has a good digest and a
		// well-formed proof; anything else is a defect in the file.
		d, okDigest := o.digest(what+" digest", c["digest"])
		index, size, _, path, why, problem := decodeProof(c["proof"])
		if !okDigest {
			continue
		}
		switch problem {
		case proofOK:
		case proofInteger, proofNode:
			o.refusalsSkipped = append(o.refusalsSkipped, fmt.Sprintf("%q (%s)", name, why))
			continue
		default:
			o.fail("%s: %s", what, why)
			continue
		}
		o.refusalsChecked++
		leafHash := h.HashLeaf(d)
		// An acceptance is counted, not failed here: the count must equal
		// oursLaxAccepts (0 for this implementation).
		accepted := false
		_, err := proof.RootFromInclusionProof(h, index, size, leafHash, path)
		if err == nil {
			accepted = true
		} else if !strings.HasPrefix(err.Error(), reason) {
			o.fail("%s: refused with %q, want the %s reason %q", what, err, errName, reason)
		}
		for _, root := range [][]byte{uncheckedChain(leafHash, index, size, path), indexBitChain(leafHash, index, path)} {
			if proof.VerifyInclusion(h, index, size, leafHash, path, root) == nil {
				accepted = true
			}
		}
		if accepted {
			o.laxAccepted = append(o.laxAccepted, name)
		}
	}
	if len(o.laxAccepted) != oursLaxAccepts {
		o.fail("walk_refusals: %d accepted (%v), constant oursLaxAccepts is %d", len(o.laxAccepted), o.laxAccepted, oursLaxAccepts)
	}
	if len(o.refusalsSkipped) != oursRefusalSkips {
		o.fail("walk_refusals: %d skipped (%s), constant oursRefusalSkips is %d", len(o.refusalsSkipped), namesOrNone(o.refusalsSkipped), oursRefusalSkips)
	}
}
