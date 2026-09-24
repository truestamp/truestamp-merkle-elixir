// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Quotes the refusal texts of computeHashFromAunts, "invalid index",
// "unexpected inner hashes" and "expected at least one inner hash", from
// github.com/cometbft/cometbft@v1.0.1 (Apache-2.0) crypto/merkle/proof.go:208,
// 215 and 220, to tell which check refused a case. License text:
// LICENSE-cometbft. See NOTICE.

package main

// -ours mode: check the truestamp_merkle library's own known answers
// (vectors/merkle.json, written by vectors/generate.exs in that repository)
// with this implementation's functions.
//
// The leaf data of an entry is the entry digest's 32 raw bytes, and a tree's
// entries are ordered by key, byte-wise ascending, before the tree is built.
//
// The sections constants, trees, walk_accepts and walk_refusals must each be
// present and non-empty, and every tree with entries must list at least one
// path. Unknown fields are ignored. A field this program reads that is missing
// or has the wrong type is a failure, never a skip.
//
//   - constants: empty_root must equal HashFromByteSlices(nil),
//     HashFromByteSlicesIterative(nil) and the ProofsFromByteSlices(empty) root.
//   - trees: every root is rebuilt with HashFromByteSlices,
//     HashFromByteSlicesIterative, ProofsFromByteSlices and the getSplitPoint /
//     innerHash recursion (impl.go). The empty tree is included: the
//     implementation represents it as HashFromByteSlices(nil) = SHA-256("").
//     depth must equal the longest path ProofsFromByteSlices produces (0 for
//     the empty and one-entry trees). Every listed path must pass
//     Proof.ValidateBasic and Proof.Verify against the root, and equal the proof
//     ProofsFromByteSlices produces for that leaf.
//   - walk_accepts: every case must pass Proof.ValidateBasic and Proof.Verify
//     against its root.
//   - walk_refusals whose error is index_out_of_range or wrong_path_length: the
//     root is the one the path reaches under an unchecked chain (the RFC 9162
//     section 2.1.3.2 loop with steps 1, 4a and the sn == 0 test of step 5
//     removed), and Proof.Verify must refuse. The count of accepted cases must
//     equal oursLaxAccepts. The digest of such a case must be 64 lowercase hex
//     characters, because the library checks the digest before the proof. Other
//     refusal errors concern the library's own input format (digest and node
//     text, step cap, JSON shape) and are not checked.
//
// Two kinds of case are skipped, counted and named on the OK line: (a) an
// in-scope walk_refusals case with a path node that is not hex, so the node has
// no byte value (the library checks the path length before it reads any node);
// (b) a case whose leaf_index or tree_size exceeds 2^63 - 1, because Proof
// carries Index and Total as int64.
//
// entry_refusals and binary_refusals concern the library's key rules and binary
// proof encoding, which this implementation has no counterpart for.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cometbft/cometbft/crypto/merkle"
)

// oursLaxAccepts is the number of in-scope walk_refusals cases that Proof.Verify
// accepts. The implementation refuses every one (computeHashFromAunts rejects
// index >= total and any path whose length differs from the tree shape before a
// root is compared), so it is 0. A change on either side that makes it accept
// one fails the run.
const oursLaxAccepts = 0

type oursCheck struct {
	fails  []string
	checks int
}

func (o *oursCheck) fail(format string, args ...any) {
	o.fails = append(o.fails, fmt.Sprintf(format, args...))
}

func (o *oursCheck) ok(cond bool, format string, args ...any) {
	o.checks++
	if !cond {
		o.fail(format, args...)
	}
}

type intStatus int

const (
	intOK       intStatus = iota
	intTooLarge           // a JSON integer outside int64: valid, but not expressible here
	intBad                // missing or not an integer (a failure has been recorded)
)

func (o *oursCheck) obj(v any, what string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		o.fail("%s: not a JSON object", what)
	}
	return m, ok
}

func (o *oursCheck) arr(m map[string]any, key, what string) ([]any, bool) {
	a, ok := m[key].([]any)
	if !ok {
		o.fail("%s: %q missing or not a JSON array", what, key)
	}
	return a, ok
}

func (o *oursCheck) str(m map[string]any, key, what string) (string, bool) {
	s, ok := m[key].(string)
	if !ok {
		o.fail("%s: %q missing or not a JSON string", what, key)
	}
	return s, ok
}

// isHex32 reports whether s is exactly 64 lowercase hexadecimal characters.
func isHex32(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (o *oursCheck) hex32(m map[string]any, key, what string) ([]byte, bool) {
	s, ok := o.str(m, key, what)
	if !ok {
		return nil, false
	}
	if !isHex32(s) {
		o.fail("%s: %q is not 64 lowercase hex characters: %q", what, key, s)
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		o.fail("%s: %q: %v", what, key, err)
		return nil, false
	}
	return b, true
}

func (o *oursCheck) hex32List(m map[string]any, key, what string) ([][]byte, bool) {
	a, ok := o.arr(m, key, what)
	if !ok {
		return nil, false
	}
	out := make([][]byte, len(a))
	good := true
	for i, v := range a {
		s, isStr := v.(string)
		if !isStr || !isHex32(s) {
			o.fail("%s: %s[%d] is not a string of 64 lowercase hex characters", what, key, i)
			good = false
			continue
		}
		out[i], _ = hex.DecodeString(s)
	}
	return out, good
}

func (o *oursCheck) integer(m map[string]any, key, what string) (int64, intStatus) {
	n, ok := m[key].(json.Number)
	if !ok {
		o.fail("%s: %q missing or not a JSON number", what, key)
		return 0, intBad
	}
	s := string(n)
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v, intOK
	}
	if _, isInt := new(big.Int).SetString(s, 10); isInt {
		return 0, intTooLarge
	}
	o.fail("%s: %q is not an integer: %s", what, key, s)
	return 0, intBad
}

// leafHashOf is the implementation's leaf hash of d: the root of the one-leaf
// tree, SHA-256(0x00 || d).
func leafHashOf(d []byte) []byte {
	return merkle.HashFromByteSlices([][]byte{d})
}

// uncheckedChainRoot runs the RFC 9162 section 2.1.3.2 loop with the range and
// length checks removed (no step 1, no step 4a, no sn == 0 test in step 5) and
// returns the hash it reaches, using the implementation's node hash. A verifier
// that skipped those checks would accept the path against this root.
func uncheckedChainRoot(index, size uint64, leafHash []byte, path [][]byte) []byte {
	fn, sn := index, size-1
	r := leafHash
	for _, p := range path {
		if fn&1 == 1 || fn == sn {
			r = cmtInnerHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = cmtInnerHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return r
}

type oursEntry struct {
	key    string
	digest []byte
}

// checkOurs reads the library's vectors at path and checks them. It returns the
// counts for the OK line, or the failures.
func checkOurs(path string) (string, []string) {
	o := &oursCheck{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", []string{"read: " + err.Error()}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return "", []string{"parse: " + err.Error()}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", []string{"parse: trailing data after the JSON document"}
	}
	top, ok := o.obj(doc, path)
	if !ok {
		return "", o.fails
	}

	// constants.empty_root
	var emptyRoot []byte
	if cv, ok := o.obj(top["constants"], "constants"); ok {
		o.ok(len(cv) > 0, "constants: empty, nothing to check")
		if er, ok := o.hex32(cv, "empty_root", "constants"); ok {
			emptyRoot = er
			o.ok(bytes.Equal(merkle.HashFromByteSlices(nil), er), "constants.empty_root differs from HashFromByteSlices(nil)")
			o.ok(bytes.Equal(merkle.HashFromByteSlicesIterative(nil), er), "constants.empty_root differs from HashFromByteSlicesIterative(nil)")
			pr, _ := merkle.ProofsFromByteSlices([][]byte{})
			o.ok(bytes.Equal(pr, er), "constants.empty_root differs from the ProofsFromByteSlices(empty) root")
		}
	}

	// trees
	nTrees, nEmpty, nPaths := 0, 0, 0
	if trees, ok := o.arr(top, "trees", "document"); ok {
		o.ok(len(trees) > 0, "trees: empty, nothing to check")
		for ti, tv := range trees {
			what := fmt.Sprintf("trees[%d]", ti)
			t, ok := o.obj(tv, what)
			if !ok {
				continue
			}
			if name, ok := o.str(t, "name", what); ok {
				what = fmt.Sprintf("tree %q", name)
			}
			ea, ok1 := o.arr(t, "entries", what)
			root, ok2 := o.hex32(t, "root", what)
			size, st1 := o.integer(t, "tree_size", what)
			depth, st2 := o.integer(t, "depth", what)
			pa, ok3 := o.arr(t, "paths", what)
			if !ok1 || !ok2 || !ok3 || st1 != intOK || st2 != intOK {
				if st1 == intTooLarge || st2 == intTooLarge {
					o.fail("%s: tree_size or depth outside int64", what)
				}
				continue
			}
			entries := make([]oursEntry, 0, len(ea))
			good := true
			for ei, ev := range ea {
				ew := fmt.Sprintf("%s entries[%d]", what, ei)
				e, ok := o.obj(ev, ew)
				if !ok {
					good = false
					continue
				}
				k, ok1 := o.str(e, "key", ew)
				d, ok2 := o.hex32(e, "digest", ew)
				if !ok1 || !ok2 {
					good = false
					continue
				}
				entries = append(entries, oursEntry{k, d})
			}
			if !good {
				continue
			}
			sort.SliceStable(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
			for i := 1; i < len(entries); i++ {
				o.ok(entries[i].key != entries[i-1].key, "%s: key %q appears twice", what, entries[i].key)
			}
			n := len(entries)
			o.ok(size == int64(n), "%s: tree_size %d, but %d entries", what, size, n)
			digests := make([][]byte, n)
			leafHashes := make([][]byte, n)
			for i, e := range entries {
				digests[i] = e.digest
				leafHashes[i] = leafHashOf(e.digest)
			}
			o.ok(bytes.Equal(merkle.HashFromByteSlices(digests), root), "%s: HashFromByteSlices gives %x, vectors say %x", what, merkle.HashFromByteSlices(digests), root)
			o.ok(bytes.Equal(merkle.HashFromByteSlicesIterative(digests), root), "%s: HashFromByteSlicesIterative differs from the root", what)
			proverRoot, proofs := merkle.ProofsFromByteSlices(digests)
			o.ok(bytes.Equal(proverRoot, root), "%s: ProofsFromByteSlices root differs from the root", what)
			o.ok(bytes.Equal(implRootFromLeafHashes(leafHashes), root), "%s: getSplitPoint/innerHash recursion differs from the root", what)
			if n == 0 {
				nEmpty++
				o.ok(emptyRoot != nil && bytes.Equal(root, emptyRoot), "%s: empty tree root differs from constants.empty_root", what)
			} else {
				o.ok(len(pa) > 0, "%s: %d entries but no paths, nothing to check", what, n)
			}
			maxAunts := 0
			for _, p := range proofs {
				maxAunts = max(maxAunts, len(p.Aunts))
			}
			o.ok(int64(maxAunts) == depth, "%s: longest ProofsFromByteSlices path has %d nodes, depth is %d", what, maxAunts, depth)
			nTrees++

			for pi, pv := range pa {
				pw := fmt.Sprintf("%s paths[%d]", what, pi)
				p, ok := o.obj(pv, pw)
				if !ok {
					continue
				}
				key, ok1 := o.str(p, "key", pw)
				digest, ok2 := o.hex32(p, "digest", pw)
				idx, st1 := o.integer(p, "leaf_index", pw)
				psize, st2 := o.integer(p, "tree_size", pw)
				nodes, ok3 := o.hex32List(p, "path", pw)
				if !ok1 || !ok2 || !ok3 || st1 != intOK || st2 != intOK {
					if st1 == intTooLarge || st2 == intTooLarge {
						o.fail("%s: leaf_index or tree_size outside int64", pw)
					}
					continue
				}
				pw = fmt.Sprintf("%s path for key %q", what, key)
				o.ok(psize == int64(n), "%s: tree_size %d, tree has %d entries", pw, psize, n)
				if idx < 0 || idx >= int64(n) {
					o.fail("%s: leaf_index %d outside the tree", pw, idx)
					continue
				}
				o.ok(entries[idx].key == key && bytes.Equal(entries[idx].digest, digest),
					"%s: leaf_index %d holds key %q in byte-wise key order", pw, idx, entries[idx].key)
				proof := merkle.Proof{Total: psize, Index: idx, LeafHash: leafHashOf(digest), Aunts: nodes}
				o.ok(proof.ValidateBasic() == nil, "%s: Proof.ValidateBasic: %v", pw, proof.ValidateBasic())
				vErr := proof.Verify(root, digest)
				o.ok(vErr == nil, "%s: Proof.Verify: %v", pw, vErr)
				own := proofs[idx]
				o.ok(own.Total == psize && own.Index == idx && bytes.Equal(own.LeafHash, proof.LeafHash) && equalAunts(own.Aunts, nodes),
					"%s: differs from the ProofsFromByteSlices proof (%d nodes vs %d)", pw, len(own.Aunts), len(nodes))
				nPaths++
			}
		}
	}

	// walk_accepts
	nAccept := 0
	var skipped []string
	if wa, ok := o.arr(top, "walk_accepts", "document"); ok {
		o.ok(len(wa) > 0, "walk_accepts: empty, nothing to check")
		for wi, wv := range wa {
			what := fmt.Sprintf("walk_accepts[%d]", wi)
			w, ok := o.obj(wv, what)
			if !ok {
				continue
			}
			if name, ok := o.str(w, "name", what); ok {
				what = fmt.Sprintf("walk_accepts %q", name)
			}
			digest, ok1 := o.hex32(w, "digest", what)
			root, ok2 := o.hex32(w, "root", what)
			_, st0 := o.integer(w, "max_steps", what)
			pr, ok3 := o.obj(w["proof"], what+" proof")
			if !ok1 || !ok2 || !ok3 || st0 == intBad {
				continue
			}
			idx, st1 := o.integer(pr, "leaf_index", what)
			size, st2 := o.integer(pr, "tree_size", what)
			nodes, ok4 := o.hex32List(pr, "path", what)
			if st1 == intBad || st2 == intBad || !ok4 {
				continue
			}
			if st1 == intTooLarge || st2 == intTooLarge {
				skipped = append(skipped, what+" (leaf_index or tree_size over 2^63 - 1)")
				continue
			}
			proof := merkle.Proof{Total: size, Index: idx, LeafHash: leafHashOf(digest), Aunts: nodes}
			o.ok(proof.ValidateBasic() == nil, "%s: Proof.ValidateBasic: %v", what, proof.ValidateBasic())
			vErr := proof.Verify(root, digest)
			o.ok(vErr == nil, "%s: Proof.Verify refuses: %v", what, vErr)
			nAccept++
		}
	}

	// walk_refusals with error index_out_of_range or wrong_path_length
	nRefused, nStructural, nOther := 0, 0, 0
	var accepted []string
	if wr, ok := o.arr(top, "walk_refusals", "document"); ok {
		o.ok(len(wr) > 0, "walk_refusals: empty, nothing to check")
		for wi, wv := range wr {
			what := fmt.Sprintf("walk_refusals[%d]", wi)
			w, ok := o.obj(wv, what)
			if !ok {
				continue
			}
			if name, ok := o.str(w, "name", what); ok {
				what = fmt.Sprintf("walk_refusals %q", name)
			}
			errName, ok := o.str(w, "error", what)
			if !ok {
				continue
			}
			if errName != "index_out_of_range" && errName != "wrong_path_length" {
				nOther++
				continue
			}
			digest, ok1 := o.hex32(w, "digest", what)
			_, st0 := o.integer(w, "max_steps", what)
			pr, ok2 := o.obj(w["proof"], what+" proof")
			if !ok1 || !ok2 || st0 == intBad {
				continue
			}
			idx, st1 := o.integer(pr, "leaf_index", what)
			size, st2 := o.integer(pr, "tree_size", what)
			pa, ok3 := o.arr(pr, "path", what)
			if st1 == intBad || st2 == intBad || !ok3 {
				continue
			}
			// Proof.Aunts is [][]byte of any length, so every node that is hex
			// is passed as the bytes it decodes to. A node that is not hex has
			// no byte value, and the case is skipped (the library refuses it
			// on path length before it reads any node).
			nodes := make([][]byte, len(pa))
			good := true
			notHex := -1
			for i, v := range pa {
				s, isStr := v.(string)
				if !isStr {
					o.fail("%s: path[%d] is not a JSON string", what, i)
					good = false
					continue
				}
				b, err := hex.DecodeString(s)
				if err != nil {
					if notHex < 0 {
						notHex = i
					}
					continue
				}
				nodes[i] = b
			}
			if !good {
				continue
			}
			if st1 == intTooLarge || st2 == intTooLarge {
				skipped = append(skipped, what+" (leaf_index or tree_size over 2^63 - 1)")
				continue
			}
			if notHex >= 0 {
				skipped = append(skipped, fmt.Sprintf("%s (path[%d] is not hex)", what, notHex))
				continue
			}
			leafHash := leafHashOf(digest)
			root := uncheckedChainRoot(uint64(idx), uint64(size), leafHash, nodes)
			proof := merkle.Proof{Total: size, Index: idx, LeafHash: leafHash, Aunts: nodes}
			if proof.Verify(root, digest) == nil {
				accepted = append(accepted, what)
			} else {
				nRefused++
			}
			if _, cErr := cmtComputeHashFromAunts(sha256.New(), idx, size, leafHash, nodes); cErr != nil {
				nStructural++
				o.ok(refusalReason(cErr) == errName, "%s: computeHashFromAunts refuses it as %s (%v), the vectors say %s",
					what, refusalReason(cErr), cErr, errName)
			} else {
				o.fail("%s: computeHashFromAunts accepts it, the vectors say %s", what, errName)
			}
		}
		o.ok(nRefused+len(accepted) > 0, "walk_refusals: no index_out_of_range or wrong_path_length case could be checked")
		o.ok(len(accepted) == oursLaxAccepts, "walk_refusals: Proof.Verify accepted %d in-scope cases, expected %d: %s",
			len(accepted), oursLaxAccepts, strings.Join(accepted, "; "))
	}

	if len(o.fails) > 0 {
		return "", o.fails
	}
	skipNote := "0 skipped"
	if len(skipped) > 0 {
		skipNote = fmt.Sprintf("%d skipped: %s", len(skipped), strings.Join(skipped, "; "))
	}
	return fmt.Sprintf("%d trees (%d empty), every root equal under HashFromByteSlices, HashFromByteSlicesIterative, ProofsFromByteSlices and the getSplitPoint/innerHash recursion, every depth equal to the longest ProofsFromByteSlices path; "+
		"%d paths pass Proof.ValidateBasic and Proof.Verify and equal ProofsFromByteSlices; "+
		"walk_accepts %d verified; "+
		"walk_refusals index_out_of_range/wrong_path_length %d refused (%d rejected by computeHashFromAunts before any root compare), %d accepted (expected %d); %d refusals with other errors not applicable; "+
		"%d checks; %s",
		nTrees, nEmpty, nPaths, nAccept,
		nRefused, nStructural, len(accepted), oursLaxAccepts, nOther, o.checks, skipNote), nil
}

// refusalReason names a computeHashFromAunts refusal the way the vectors do,
// from its text in crypto/merkle/proof.go:208, 215 and 220.
func refusalReason(err error) string {
	switch msg := err.Error(); {
	case strings.HasPrefix(msg, "invalid index "):
		return "index_out_of_range"
	case msg == "unexpected inner hashes", msg == "expected at least one inner hash":
		return "wrong_path_length"
	default:
		return "an unrecognized refusal"
	}
}
