// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains material from github.com/codenotary/merkletree@v0.1.2: case names
// and comments below quote short code fragments of tree.go, mth_test.go,
// tree_test.go and example_test.go and cite those files by line, Copyright
// 2019-2020 vChain, Inc., licensed under the Apache License, Version 2.0
// (LICENSE-codenotary-merkletree; see NOTICE).

// Command codenotary-merkletree regenerates and checks the interop fixture for
// github.com/codenotary/merkletree v0.1.2 (Apache-2.0), an RFC 6962 / RFC 9162
// section 2.1 Merkle tree in Go by vChain, Inc. (Codenotary). In the
// truestamp_merkle repository it lives at interop/go/codenotary-merkletree/
// and its fixture at vectors/interop/codenotary-merkletree.json.
//
//	go run . -fixtures <path>          check the file: one "OK fixtures ..."
//	                                   line, or "FAIL fixtures ..." lines and
//	                                   exit status 1
//	go run . -fixtures <path> -write   regenerate the file from the vendored
//	                                   upstream literals and the module, then
//	                                   check it
//	go run . -fixtures <path> -ours <merkle.json>
//	                                   also check truestamp_merkle's own
//	                                   vectors with the module's functions
//	                                   (ours.go): an "OK ours ..." line, or
//	                                   "FAIL ours ..." lines
//
// From the program directory, the fixture is regenerated with
//
//	go run . -fixtures ../../../vectors/interop/codenotary-merkletree.json -write
//
// -fixtures is required. Apart from the -fixtures and -ours paths the program
// reads nothing outside its own module directory: the upstream literals and
// test code it needs are vendored under testdata/ and embedded. A bad command
// line prints one "FAIL usage: ..." line; every other failure, including a
// malformed file, prints "FAIL fixtures ..." or "FAIL ours ..." lines. Either
// way the exit status is 1. -h prints the usage to stderr and exits 0.
//
// Where the values come from:
//   - Published values are the literals of data_test.go (testRoots, testPaths),
//     compiled from a verbatim copy (upstream_data.go), and the verdicts that
//     upstream's own test code asserts, recorded by running verbatim copies of
//     the tests (upstream_tests.go) against the real module.
//   - Every other hash is computed by the module from upstream leaf data:
//     merkletree.LeafHash, merkletree.MTH, merkletree.MPath,
//     merkletree.InclusionProof, and merkletree.AppendHash / merkletree.Root on
//     a two-leaf store for a node hash of two given hashes.
//   - "valid" is always merkletree.Path.VerifyInclusion's return value.
//   - "rfc9162_valid" comes from reference.go, an RFC 9162 section 2.1.3.2
//     verifier written from the RFC text, and appears only where the module's
//     verdict differs from it.
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
	"reflect"
	"strconv"
	"strings"

	cn "github.com/codenotary/merkletree"
)

const (
	modulePath    = "github.com/codenotary/merkletree"
	moduleVersion = "v0.1.2"
	moduleLicense = "Apache-2.0"
)

// ---------------------------------------------------------------------------
// Fixture schema
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

type h32 = [sha256.Size]byte

func hx(b []byte) string { return hex.EncodeToString(b) }
func hx32(b h32) string  { return hex.EncodeToString(b[:]) }
func strp(s string) *string {
	return &s
}
func boolp(b bool) *bool { return &b }

func hexPath(p [][sha256.Size]byte) []string {
	out := make([]string, len(p))
	for i := range p {
		out[i] = hx32(p[i])
	}
	return out
}

func slices(p [][sha256.Size]byte) [][]byte {
	out := make([][]byte, len(p))
	for i := range p {
		b := p[i]
		out[i] = b[:]
	}
	return out
}

// decimalData is the leaf data rule of every upstream test over testRoots:
// leaf i is []byte(strconv.FormatUint(i, 10)) (mth_test.go:33,
// tree_test.go:51, 92, 132).
func decimalData(n uint64) [][]byte {
	D := make([][]byte, n)
	for i := uint64(0); i < n; i++ {
		D[i] = []byte(strconv.FormatUint(i, 10))
	}
	return D
}

// nodeHash returns SHA-256(0x01 || left || right) as the module computes it:
// merkletree.AppendHash of left then right into an empty store builds the
// parent at tree.go:74-82, and merkletree.Root returns it.
func nodeHash(left, right h32) h32 {
	s := cn.NewMemStore()
	l, r := left, right
	cn.AppendHash(s, &l)
	cn.AppendHash(s, &r)
	return cn.Root(s)
}

// storeRootFromData builds the incremental store with merkletree.Append and
// returns merkletree.Root.
func storeRootFromData(D [][]byte) h32 {
	s := cn.NewMemStore()
	for _, b := range D {
		cn.Append(s, b)
	}
	return cn.Root(s)
}

// storeRootFromHashes builds the store from leaf hashes with
// merkletree.AppendHash.
func storeRootFromHashes(lh []h32) h32 {
	s := cn.NewMemStore()
	for _, h := range lh {
		x := h
		cn.AppendHash(s, &x)
	}
	return cn.Root(s)
}

func verify(path [][sha256.Size]byte, leafIndex, treeSize uint64, root, leaf h32) bool {
	return cn.Path(path).VerifyInclusion(treeSize-1, leafIndex, root, leaf)
}

func quoteData(b []byte) string { return strconv.Quote(string(b)) }

func refSplitK(n uint64) uint64 {
	if n < 2 {
		return 0
	}
	return refSplit(n)
}

// ---------------------------------------------------------------------------
// Building the fixture
// ---------------------------------------------------------------------------

type buildStats struct {
	published, generated     int
	truncAccepted, extended  int
	truncRejectedAll         int
	truncControl             int
	loopUnique, loopKept     int
	loopCallsDeduplicated    int
	rfcOverrides             int
	upstreamCallsRecorded    int
	inclusionProofComparable int
}

// loopKeep selects the deterministic subset of the TestVerifyInclusion loop
// (tree_test.go:131-145) written for sizes 10..65: every leaf of sizes
// 10..32 (the sizes the discrepancy cases cover, so each of those has its
// valid baseline), and leaves 0, k-1, k and n-1 of sizes 33..65 (k is the
// largest power of two smaller than n: the first and last leaf of the left
// subtree and of the right subtree). Sizes 1..9 are written as the
// published testPaths cases.
func loopKeep(n, m uint64) bool {
	if n <= 32 {
		return true
	}
	k := refSplitK(n)
	return m == 0 || m == k-1 || m == k || m == n-1
}

func build() (*Fixture, *buildStats, error) {
	st := &buildStats{}
	if err := checkVendored(); err != nil {
		return nil, nil, err
	}
	if err := loadBlocks(); err != nil {
		return nil, nil, err
	}
	dl, err := locateData()
	if err != nil {
		return nil, nil, err
	}
	if err := runUpstreamTests(); err != nil {
		return nil, nil, err
	}
	st.upstreamCallsRecorded = len(recorded)

	D := decimalData(65)
	lh := make([]h32, 65)
	lhs := make([][]byte, 65)
	for i := range D {
		lh[i] = cn.LeafHash(D[i])
		lhs[i] = lh[i][:]
	}

	// Every published root is the RFC 9162 MTH, and cn reproduces it both ways.
	for j := 0; j < 65; j++ {
		n := j + 1
		if cn.MTH(D[:n]) != testRoots[j] || storeRootFromData(D[:n]) != testRoots[j] {
			return nil, nil, fmt.Errorf("module does not reproduce testRoots[%d]", j)
		}
		if !bytes.Equal(refMTH(lhs[:n]), testRoots[j][:]) {
			return nil, nil, fmt.Errorf("testRoots[%d] is not the RFC 9162 MTH", j)
		}
	}
	// Every published path is the RFC 9162 PATH, and MPath reproduces it.
	for idx := range testPaths {
		n := uint64(idx + 1)
		for i := range testPaths[idx] {
			if !reflect.DeepEqual(cn.MPath(uint64(i), D[:n]), testPaths[idx][i]) {
				return nil, nil, fmt.Errorf("MPath does not reproduce testPaths[%d][%d]", idx, i)
			}
			if !reflect.DeepEqual(refPath(uint64(i), lhs[:n]), slices(testPaths[idx][i])) {
				return nil, nil, fmt.Errorf("testPaths[%d][%d] is not the RFC 9162 PATH", idx, i)
			}
		}
	}

	f := &Fixture{
		Implementation: modulePath,
		Version:        moduleVersion,
		License:        moduleLicense,
		Sources:        sources(),
	}

	// empty_root: mth_test.go:31 asserts MTH([]) == sha256.Sum256(nil);
	// tree_test.go:64 asserts the same for Root of an empty store.
	e := cn.MTH(nil)
	if e != cn.Root(cn.NewMemStore()) || !bytes.Equal(e[:], refMTH(nil)) {
		return nil, nil, errors.New("empty root disagreement")
	}
	f.EmptyRoot = strp(hx32(e))

	// ---------------------------------------------------------- hash_checks
	for i := 0; i <= 8; i++ {
		where, ok := dl.byValue[lh[i]]
		if !ok {
			return nil, nil, fmt.Errorf("leaf hash of %q has no literal in data_test.go", D[i])
		}
		f.HashChecks = append(f.HashChecks, HashCheck{
			Name:     fmt.Sprintf("published: leaf hash of %s (decimal ASCII leaf data, mth_test.go:33), literal at %s", quoteData(D[i]), where),
			Kind:     "leaf",
			InputHex: strp(hx(D[i])),
			Hash:     hx32(lh[i]),
		})
	}
	someValue := []byte("some value")
	f.HashChecks = append(f.HashChecks, HashCheck{
		Name:     "generated: leaf hash of \"some value\" (tree_test.go:66-68 TestRoot asserts Root of the 1-leaf store == LeafHash(value); no hash literal upstream)",
		Kind:     "leaf",
		InputHex: strp(hx(someValue)),
		Hash:     hx32(cn.LeafHash(someValue)),
	})
	for n := uint64(2); n <= 65; n++ {
		k := refSplit(n)
		left := testRoots[k-1]
		right := cn.MTH(D[k:n])
		if nodeHash(left, right) != testRoots[n-1] {
			return nil, nil, fmt.Errorf("node check for size %d fails", n)
		}
		rightWhere := "computed by merkletree.MTH from the leaf data"
		if w, ok := dl.byValue[right]; ok {
			rightWhere = "literal at " + w
		}
		rightWhat := fmt.Sprintf("MTH of %s..%s", quoteData(D[k]), quoteData(D[n-1]))
		if k == n-1 {
			rightWhat = "leaf hash of " + quoteData(D[k])
		}
		f.HashChecks = append(f.HashChecks, HashCheck{
			Name: fmt.Sprintf("published: data_test.go:%d testRoots[%d] (size %d root) = node(left: data_test.go:%d testRoots[%d], right: %s, %s)",
				dl.rootLine[n-1], n-1, n, dl.rootLine[k-1], k-1, rightWhat, rightWhere),
			Kind:  "node",
			Left:  strp(hx32(left)),
			Right: strp(hx32(right)),
			Hash:  hx32(testRoots[n-1]),
		})
	}

	// ---------------------------------------------------------------- trees
	f.Trees = append(f.Trees, Tree{
		Name:       "published: empty tree (mth_test.go:31 TestMTH asserts MTH([]) == sha256.Sum256(nil); tree_test.go:64 TestRoot asserts Root(NewMemStore()) == sha256.Sum256(nil))",
		LeafData:   []string{},
		LeafHashes: []string{},
		TreeSize:   0,
		Root:       hx32(e),
	})
	for j := 0; j < 65; j++ {
		n := j + 1
		f.Trees = append(f.Trees, Tree{
			Name: fmt.Sprintf("published: data_test.go:%d testRoots[%d], size %d, leaf data decimal ASCII \"0\"..%s (mth_test.go:32-35 TestMTH, tree_test.go:50-58 TestAppend)",
				dl.rootLine[j], j, n, quoteData(D[j])),
			LeafData:     nil,
			LeafHashes:   nil,
			LeafDataRule: &LeafDataRule{Encoding: "decimal_ascii", First: 0},
			TreeSize:     uint64(n),
			Root:         hx32(testRoots[j]),
		})
	}
	// example_test.go:43-70 make7leaves: leaves "d0".."d6".
	var D7 [][]byte
	for i := 0; i < 7; i++ {
		D7 = append(D7, []byte("d"+strconv.FormatInt(int64(i), 10)))
	}
	m7, D7up, s7 := make7leaves()
	if !reflect.DeepEqual(D7, D7up) {
		return nil, nil, errors.New("make7leaves leaf data differs")
	}
	root7 := cn.MTH(D7)
	if root7 != m7["hash"] || root7 != cn.Root(s7) {
		return nil, nil, errors.New("make7leaves root differs")
	}
	var d7hex, lh7hex []string
	var lh7 []h32
	for _, b := range D7 {
		d7hex = append(d7hex, hx(b))
		lh7 = append(lh7, cn.LeafHash(b))
		lh7hex = append(lh7hex, hx32(cn.LeafHash(b)))
	}
	f.Trees = append(f.Trees, Tree{
		Name:       "generated: example_test.go:43-70 make7leaves, 7 leaves \"d0\"..\"d6\" (root m[\"hash\"] = store node (3, 0); no hash literal upstream)",
		LeafData:   d7hex,
		LeafHashes: lh7hex,
		TreeSize:   7,
		Root:       hx32(root7),
	})
	f.Trees = append(f.Trees, Tree{
		Name:       "generated: tree_test.go:62-69 TestRoot, 1 leaf \"some value\" (Root == LeafHash(value); no hash literal upstream)",
		LeafData:   []string{hx(someValue)},
		LeafHashes: []string{hx32(cn.LeafHash(someValue))},
		TreeSize:   1,
		Root:       hx32(cn.LeafHash(someValue)),
	})

	// ------------------------------------------------------------ inclusion
	add := func(c Inclusion, published bool) error {
		leaf, err := dec32(c.LeafHash)
		if err != nil {
			return err
		}
		root, err := dec32(c.Root)
		if err != nil {
			return err
		}
		path, err := decPath(c.Path)
		if err != nil {
			return err
		}
		v := verify(path, c.LeafIndex, c.TreeSize, root, leaf)
		if v != c.Valid {
			return fmt.Errorf("%s: module verdict %v, built as %v", c.Name, v, c.Valid)
		}
		ref := refVerify(leaf[:], c.LeafIndex, c.TreeSize, slices(path), root[:])
		if ref != v {
			c.RFC9162Valid = boolp(ref)
			st.rfcOverrides++
		}
		if published {
			st.published++
		} else {
			st.generated++
		}
		f.Inclusion = append(f.Inclusion, c)
		return nil
	}

	// Recorded upstream calls, by (at, i) for the loop, by line otherwise.
	type key struct{ at, i uint64 }
	loop := map[key]*verifyCall{}
	var loopOrder []key
	var edge, example []*verifyCall
	for _, c := range recorded {
		switch {
		case c.file == "tree_test.go" && c.line == 138:
			k := key{c.at, c.i}
			if prev, ok := loop[k]; ok {
				if !reflect.DeepEqual(prev.path, c.path) || prev.root != c.root || prev.leaf != c.leaf || prev.result != c.result {
					return nil, nil, fmt.Errorf("loop call (at %d, i %d) differs between store widths", c.at, c.i)
				}
				st.loopCallsDeduplicated++
				continue
			}
			loop[k] = c
			loopOrder = append(loopOrder, k)
		case c.file == "tree_test.go" && (c.line == 123 || c.line == 125 || c.line == 126 || c.line == 127):
			edge = append(edge, c)
		case c.file == "example_test.go" && (c.line == 82 || c.line == 91 || c.line == 107):
			example = append(example, c)
		default:
			return nil, nil, fmt.Errorf("unexpected recorded call at %s:%d", c.file, c.line)
		}
	}
	st.loopUnique = len(loop)
	if len(loop) != 2145 || len(edge) != 4 || len(example) != 3 {
		return nil, nil, fmt.Errorf("recorded %d loop, %d edge, %d example calls", len(loop), len(edge), len(example))
	}

	// (a) The 4 published edge verdicts, tree_test.go:123-127.
	for _, c := range edge {
		exp := "invalid"
		if *c.asserted {
			exp = "valid"
		}
		stmt := "assert.False"
		if *c.asserted {
			stmt = "assert.True"
		}
		name := fmt.Sprintf("published: tree_test.go:%d TestVerifyInclusion %s(Path{}.VerifyInclusion(at=%d, i=%d, zero root, zero leaf)): leaf_index %d, tree_size %d, empty path, all-zero leaf hash and root",
			c.line, stmt, c.at, c.i, c.i, c.at+1)
		if err := add(Inclusion{
			Name: name, LeafHash: hx32(c.leaf), LeafIndex: c.i, TreeSize: c.at + 1,
			Path: hexPath(c.path), Root: hx32(c.root), Valid: c.result, UpstreamExpectation: exp,
		}, true); err != nil {
			return nil, nil, err
		}
	}

	// (b) The 45 published testPaths, sizes 1..9.
	for idx := range testPaths {
		n := uint64(idx + 1)
		for i := range testPaths[idx] {
			c := loop[key{uint64(idx), uint64(i)}]
			if c == nil || !reflect.DeepEqual(c.path, testPaths[idx][i]) || c.root != testRoots[idx] || c.leaf != lh[i] {
				return nil, nil, fmt.Errorf("loop call for testPaths[%d][%d] does not match the literal", idx, i)
			}
			span := dl.pathSpan[idx][i]
			name := fmt.Sprintf("published: data_test.go:%s testPaths[%d][%d]: leaf %d (%s) of size %d, root data_test.go:%d testRoots[%d]; mth_test.go:58 asserts MPath == this path, tree_test.go:138-139 asserts VerifyInclusion(at=%d, i=%d) true",
				lineRange(span[0], span[1]), idx, i, i, quoteData(D[i]), n, dl.rootLine[idx], idx, idx, i)
			if err := add(Inclusion{
				Name: name, LeafHash: hx32(lh[i]), LeafIndex: uint64(i), TreeSize: n,
				Path: hexPath(testPaths[idx][i]), Root: hx32(testRoots[idx]), Valid: c.result,
				UpstreamExpectation: expectation(c),
			}, true); err != nil {
				return nil, nil, err
			}
		}
	}

	// (c) The TestVerifyInclusion loop for sizes 10..65 (deterministic subset).
	for _, k := range loopOrder {
		n := k.at + 1
		if n <= 9 {
			continue
		}
		if !loopKeep(n, k.i) {
			continue
		}
		c := loop[k]
		if c.root != testRoots[k.at] || c.leaf != lh[k.i] || !reflect.DeepEqual(c.path, cn.MPath(k.i, D[:n])) {
			return nil, nil, fmt.Errorf("loop call (at %d, i %d) inputs differ", k.at, k.i)
		}
		name := fmt.Sprintf("generated: tree_test.go:137-139 TestVerifyInclusion loop asserts true: size %d, leaf %d, path MPath(%d, D[0:%d]), root data_test.go:%d testRoots[%d]",
			n, k.i, k.i, n, dl.rootLine[k.at], k.at)
		if err := add(Inclusion{
			Name: name, LeafHash: hx32(c.leaf), LeafIndex: k.i, TreeSize: n,
			Path: hexPath(c.path), Root: hx32(c.root), Valid: c.result, UpstreamExpectation: expectation(c),
		}, false); err != nil {
			return nil, nil, err
		}
		st.loopKept++
	}

	// (d) example_test.go:72-108 TestInclusionPath over make7leaves.
	letters := map[h32]string{}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "hash"} {
		letters[m7[name]] = name
	}
	pathLetters := func(p [][sha256.Size]byte) string {
		var ls []string
		for _, h := range p {
			ls = append(ls, letters[h])
		}
		return "[" + strings.Join(ls, ", ") + "]"
	}
	exampleLines := map[uint64]string{0: "76-82", 3: "85-91", 4: "94-99", 6: "102-107"}
	for _, i := range []uint64{0, 3, 4, 6} {
		p := cn.InclusionProof(s7, 6, i)
		if !eqPath(p, cn.MPath(i, D7)) {
			return nil, nil, errors.New("make7leaves: InclusionProof differs from MPath")
		}
		var c *verifyCall
		for _, x := range example {
			if x.i == i {
				c = x
			}
		}
		exp := "none"
		how := "asserts the path but never calls VerifyInclusion"
		if c != nil {
			if c.at != 6 || !reflect.DeepEqual(c.path, [][sha256.Size]byte(p)) || c.root != root7 || c.leaf != lh7[i] {
				return nil, nil, errors.New("make7leaves: recorded call differs")
			}
			exp = expectation(c)
			how = fmt.Sprintf("line %d asserts VerifyInclusion(6, %d) true", c.line, i)
		}
		name := fmt.Sprintf("generated: example_test.go:%s TestInclusionPath: leaf %d (\"d%d\") of the 7-leaf make7leaves tree, path InclusionProof(s, 6, %d) = %s, root m[\"hash\"]; upstream %s",
			exampleLines[i], i, i, i, pathLetters(p), how)
		if err := add(Inclusion{
			Name: name, LeafHash: hx32(lh7[i]), LeafIndex: i, TreeSize: 7,
			Path: hexPath(p), Root: hx32(root7), Valid: verify(p, i, 7, root7, lh7[i]), UpstreamExpectation: exp,
		}, false); err != nil {
			return nil, nil, err
		}
	}

	// (e) DISCREPANCY: right-edge truncated paths, sizes 1..32. For every
	// proper prefix (length L >= 1) of every MPath, the only root the
	// verifier could accept is the hash it holds after L steps, which is the
	// MTH of the RFC 9162 subtree the prefix commits to. The module accepts
	// exactly when (m >> L) == ((n-1) >> L), which tree.go:214 checks as
	// at == i. RFC 9162 section 2.1.3.2 rejects every one (sn != 0 when the
	// path runs out). Rejected prefixes of leaf 0 are kept as a control.
	for n := uint64(1); n <= 32; n++ {
		for m := uint64(0); m < n; m++ {
			full := cn.MPath(m, D[:n])
			ranges := refRanges(m, n)
			if len(ranges) != len(full)+1 {
				return nil, nil, fmt.Errorf("size %d leaf %d: ranges %d, path %d", n, m, len(ranges), len(full))
			}
			for L := 1; L < len(full); L++ {
				r := ranges[len(full)-L]
				root := cn.MTH(D[r[0]:r[1]])
				prefix := full[:L]
				v := verify(prefix, m, n, root, lh[m])
				if v != ((m >> uint(L)) == ((n - 1) >> uint(L))) {
					return nil, nil, fmt.Errorf("size %d leaf %d prefix %d: verdict %v breaks the at == i rule", n, m, L, v)
				}
				if v {
					if r[1] != n {
						return nil, nil, fmt.Errorf("size %d leaf %d prefix %d: accepted root is not a right-edge subtree", n, m, L)
					}
					st.truncAccepted++
					name := fmt.Sprintf("generated: DISCREPANCY right-edge truncated path: size %d, leaf %d, first %d of the %d elements of MPath(%d, D[0:%d]), root = MTH of leaves %d..%d; module accepts, RFC 9162 rejects (discrepancies[0])",
						n, m, L, len(full), m, n, r[0], r[1]-1)
					if err := add(Inclusion{
						Name: name, LeafHash: hx32(lh[m]), LeafIndex: m, TreeSize: n,
						Path: hexPath(prefix), Root: hx32(root), Valid: v, UpstreamExpectation: "none",
					}, false); err != nil {
						return nil, nil, err
					}
				} else {
					st.truncRejectedAll++
					if m == 0 {
						st.truncControl++
						name := fmt.Sprintf("generated: truncation control: size %d, leaf 0, first %d of the %d elements of MPath(0, D[0:%d]), root = MTH of leaves %d..%d (not on the right edge); module and RFC 9162 both reject",
							n, L, len(full), n, r[0], r[1]-1)
						if err := add(Inclusion{
							Name: name, LeafHash: hx32(lh[m]), LeafIndex: m, TreeSize: n,
							Path: hexPath(prefix), Root: hx32(root), Valid: v, UpstreamExpectation: "none",
						}, false); err != nil {
							return nil, nil, err
						}
					}
				}
			}
		}
	}

	// (f) DISCREPANCY: over-long paths, sizes 1..32. MPath plus one extra
	// element (the leaf hash of "0"), with the root the verifier then holds:
	// node(extra, testRoots[n-1]).
	for n := uint64(1); n <= 32; n++ {
		for m := uint64(0); m < n; m++ {
			full := cn.MPath(m, D[:n])
			extra := lh[0]
			long := append(append([][sha256.Size]byte{}, full...), extra)
			root := nodeHash(extra, testRoots[n-1])
			v := verify(long, m, n, root, lh[m])
			if !v {
				return nil, nil, fmt.Errorf("size %d leaf %d: over-long path rejected", n, m)
			}
			st.extended++
			name := fmt.Sprintf("generated: DISCREPANCY over-long path: size %d, leaf %d, the %d elements of MPath(%d, D[0:%d]) plus the leaf hash of \"0\", root = node(leaf hash of \"0\", testRoots[%d]); module accepts, RFC 9162 rejects (discrepancies[1])",
				n, m, len(full), m, n, n-1)
			if err := add(Inclusion{
				Name: name, LeafHash: hx32(lh[m]), LeafIndex: m, TreeSize: n,
				Path: hexPath(long), Root: hx32(root), Valid: v, UpstreamExpectation: "none",
			}, false); err != nil {
				return nil, nil, err
			}
		}
	}

	// InclusionProof on the full 65-leaf store equals MPath for every
	// (at, i): TestInclusionProof already asserted this for every store
	// width; count the pairs once more here.
	s65 := cn.NewMemStore()
	for _, b := range D {
		cn.Append(s65, b)
	}
	for at := uint64(0); at < 65; at++ {
		for i := uint64(0); i <= at; i++ {
			if !eqPath(cn.InclusionProof(s65, at, i), cn.MPath(i, D[:at+1])) {
				return nil, nil, fmt.Errorf("InclusionProof(s65, %d, %d) differs from MPath", at, i)
			}
			st.inclusionProofComparable++
		}
	}

	f.Deviations = []string{}
	f.Discrepancies = discrepancies(st)
	f.Notes = notes(st)
	return f, st, nil
}

// eqPath compares two paths element by element (the module returns a nil
// Path from InclusionProof for a 1-leaf tree and an empty one from MPath).
func eqPath(a, b [][sha256.Size]byte) bool {
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

func expectation(c *verifyCall) string {
	if c.asserted == nil {
		return "none"
	}
	if *c.asserted {
		return "valid"
	}
	return "invalid"
}

func dec32(s string) (h32, error) {
	var out h32
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 || hx(b) != s {
		return out, fmt.Errorf("not 64 lowercase hex characters: %q", s)
	}
	copy(out[:], b)
	return out, nil
}

func decPath(p []string) ([][sha256.Size]byte, error) {
	if p == nil {
		return nil, errors.New("path is null")
	}
	out := make([][sha256.Size]byte, len(p))
	for i, s := range p {
		h, err := dec32(s)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

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

const sizeBudget = 1_500_000

// maxRuleLeaves bounds the leaves a leaf_data_rule tree may expand to, so a
// malformed tree_size fails instead of exhausting memory (the largest tree
// here has 65 leaves).
const maxRuleLeaves = 1 << 16

// ---------------------------------------------------------------------------
// Checking a fixture file
// ---------------------------------------------------------------------------

type checkCounts struct {
	hashChecks, trees, inclusion, valid, invalid, overrides int
	published, generated                                    int
	values                                                  int
}

// evaluate re-derives every value in f with the module's own functions,
// independently of how build() produced it.
func evaluate(f *Fixture) (checkCounts, []string) {
	var cc checkCounts
	var fails []string
	bad := func(format string, a ...interface{}) { fails = append(fails, fmt.Sprintf(format, a...)) }

	if f.Implementation != modulePath || f.Version != moduleVersion || f.License != moduleLicense {
		bad("header: implementation %q version %q license %q", f.Implementation, f.Version, f.License)
	}
	if f.EmptyRoot == nil {
		bad("empty_root is null")
	} else {
		e := cn.MTH(nil)
		if *f.EmptyRoot != hx32(e) || *f.EmptyRoot != hx32(cn.Root(cn.NewMemStore())) {
			bad("empty_root %s is not merkletree.MTH(nil) / Root(empty store)", *f.EmptyRoot)
		}
		cc.values++
	}

	for _, hc := range f.HashChecks {
		cc.hashChecks++
		want, err := dec32(hc.Hash)
		if err != nil {
			bad("hash_check %q: %v", hc.Name, err)
			continue
		}
		switch hc.Kind {
		case "leaf":
			if hc.InputHex == nil || hc.Left != nil || hc.Right != nil {
				bad("hash_check %q: leaf needs input_hex only", hc.Name)
				continue
			}
			in, err := hex.DecodeString(*hc.InputHex)
			if err != nil || hx(in) != *hc.InputHex {
				bad("hash_check %q: bad input_hex", hc.Name)
				continue
			}
			if cn.LeafHash(in) != want {
				bad("hash_check %q: merkletree.LeafHash gives %s", hc.Name, hx32(cn.LeafHash(in)))
			}
		case "node":
			if hc.InputHex != nil || hc.Left == nil || hc.Right == nil {
				bad("hash_check %q: node needs left and right only", hc.Name)
				continue
			}
			l, err1 := dec32(*hc.Left)
			r, err2 := dec32(*hc.Right)
			if err1 != nil || err2 != nil {
				bad("hash_check %q: bad left/right", hc.Name)
				continue
			}
			if nodeHash(l, r) != want {
				bad("hash_check %q: merkletree node hash gives %s", hc.Name, hx32(nodeHash(l, r)))
			}
		default:
			bad("hash_check %q: kind %q", hc.Name, hc.Kind)
		}
		cc.values++
	}

	for _, t := range f.Trees {
		cc.trees++
		root, err := dec32(t.Root)
		if err != nil {
			bad("tree %q: %v", t.Name, err)
			continue
		}
		var data [][]byte
		haveData := false
		switch {
		case t.LeafDataRule != nil:
			if t.LeafData != nil || t.LeafHashes != nil {
				bad("tree %q: leaf_data_rule with leaf_data or leaf_hashes", t.Name)
				continue
			}
			if t.TreeSize > maxRuleLeaves {
				bad("tree %q: tree_size %d is over the %d leaves a leaf_data_rule tree may expand to", t.Name, t.TreeSize, maxRuleLeaves)
				continue
			}
			if t.LeafDataRule.Encoding != "decimal_ascii" {
				bad("tree %q: encoding %q is not used in this file", t.Name, t.LeafDataRule.Encoding)
				continue
			}
			for i := uint64(0); i < t.TreeSize; i++ {
				data = append(data, []byte(strconv.FormatUint(t.LeafDataRule.First+i, 10)))
			}
			haveData = true
		case t.LeafData != nil:
			for _, s := range t.LeafData {
				b, err := hex.DecodeString(s)
				if err != nil || hx(b) != s {
					bad("tree %q: bad leaf_data", t.Name)
				}
				data = append(data, b)
			}
			haveData = true
		}
		if haveData {
			if uint64(len(data)) != t.TreeSize {
				bad("tree %q: %d leaves, tree_size %d", t.Name, len(data), t.TreeSize)
				continue
			}
			if cn.MTH(data) != root {
				bad("tree %q: merkletree.MTH gives %s", t.Name, hx32(cn.MTH(data)))
			}
			if storeRootFromData(data) != root {
				bad("tree %q: merkletree.Append/Root gives %s", t.Name, hx32(storeRootFromData(data)))
			}
		}
		if t.LeafHashes != nil {
			if uint64(len(t.LeafHashes)) != t.TreeSize {
				bad("tree %q: %d leaf hashes, tree_size %d", t.Name, len(t.LeafHashes), t.TreeSize)
				continue
			}
			var lh []h32
			for i, s := range t.LeafHashes {
				h, err := dec32(s)
				if err != nil {
					bad("tree %q: %v", t.Name, err)
					continue
				}
				if haveData && cn.LeafHash(data[i]) != h {
					bad("tree %q: leaf_hashes[%d] is not merkletree.LeafHash(leaf_data[%d])", t.Name, i, i)
				}
				lh = append(lh, h)
			}
			if storeRootFromHashes(lh) != root {
				bad("tree %q: merkletree.AppendHash/Root over leaf_hashes gives %s", t.Name, hx32(storeRootFromHashes(lh)))
			}
		} else if !haveData {
			bad("tree %q: no leaves", t.Name)
		}
		cc.values++
	}

	for _, c := range f.Inclusion {
		cc.inclusion++
		switch {
		case strings.HasPrefix(c.Name, "published: "):
			cc.published++
		case strings.HasPrefix(c.Name, "generated: "):
			cc.generated++
		default:
			bad("inclusion %q: name must start with published: or generated:", c.Name)
		}
		leaf, err1 := dec32(c.LeafHash)
		root, err2 := dec32(c.Root)
		path, err3 := decPath(c.Path)
		if err1 != nil || err2 != nil || err3 != nil {
			bad("inclusion %q: bad hex", c.Name)
			continue
		}
		if c.TreeSize == 0 {
			bad("inclusion %q: tree_size 0 cannot be expressed as at = tree_size - 1", c.Name)
			continue
		}
		v := verify(path, c.LeafIndex, c.TreeSize, root, leaf)
		if v != c.Valid {
			bad("inclusion %q: merkletree.Path.VerifyInclusion returns %v, file says %v", c.Name, v, c.Valid)
		}
		ref := refVerify(leaf[:], c.LeafIndex, c.TreeSize, slices(path), root[:])
		switch {
		case ref == v && c.RFC9162Valid != nil:
			bad("inclusion %q: rfc9162_valid present but the RFC 9162 answer equals the module's", c.Name)
		case ref != v && (c.RFC9162Valid == nil || *c.RFC9162Valid != ref):
			bad("inclusion %q: RFC 9162 answer %v differs from the module's; rfc9162_valid must say so", c.Name, ref)
		}
		if ref != v {
			cc.overrides++
		}
		switch c.UpstreamExpectation {
		case "valid", "invalid":
			if (c.UpstreamExpectation == "valid") != v {
				bad("inclusion %q: upstream expects %s, module says %v (not recorded as a discrepancy)", c.Name, c.UpstreamExpectation, v)
			}
		case "none":
		default:
			bad("inclusion %q: upstream_expectation %q", c.Name, c.UpstreamExpectation)
		}
		if v {
			cc.valid++
		} else {
			cc.invalid++
		}
		cc.values++
	}
	return cc, fails
}

func check(path string, want []byte, wantF *Fixture, st *buildStats) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		failf("fixtures", "%s: %v", path, err)
		return false
	}
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		failf("fixtures", "%s: %v", path, err)
		return false
	}
	if dec.More() {
		failf("fixtures", "%s: trailing data after the JSON object", path)
		return false
	}
	ok := true
	cc, fails := evaluate(&f)
	for _, s := range fails {
		failf("fixtures", "%s", s)
		ok = false
	}
	if !bytes.Equal(raw, want) {
		ok = false
		failf("fixtures", "%s differs from the regenerated fixture (%d bytes, regenerated %d)", path, len(raw), len(want))
		reportDiff(&f, wantF)
	}
	if len(raw) > sizeBudget {
		ok = false
		failf("fixtures", "%s is %d bytes, over the %d byte budget", path, len(raw), sizeBudget)
	}
	if !ok {
		return false
	}
	fmt.Printf("OK fixtures %s@%s: empty_root 1, hash_checks %d, trees %d, inclusion %d (published %d, generated %d; valid %d, invalid %d; rfc9162_valid overrides %d: %d right-edge truncated + %d over-long), %d values re-derived with the module, %d recorded upstream VerifyInclusion calls all as asserted, %d InclusionProof/MPath pairs equal, 9 verbatim blocks, fixture byte-identical to regeneration (%d bytes)\n",
		modulePath, moduleVersion, cc.hashChecks, cc.trees, cc.inclusion, cc.published, cc.generated, cc.valid, cc.invalid,
		cc.overrides, st.truncAccepted, st.extended, cc.values, st.upstreamCallsRecorded, st.inclusionProofComparable, len(raw))
	return true
}

// reportDiff prints one FAIL line for each part of the file that differs from
// the regenerated fixture, at most 20.
func reportDiff(got, want *Fixture) {
	shown := 0
	line := func(format string, a ...interface{}) {
		if shown < 20 {
			failf("fixtures", "differs from the regenerated fixture: "+format, a...)
		}
		shown++
	}
	if !reflect.DeepEqual(got.Sources, want.Sources) {
		line("sources differ")
	}
	if !reflect.DeepEqual(got.EmptyRoot, want.EmptyRoot) {
		line("empty_root differs")
	}
	if !reflect.DeepEqual(got.Deviations, want.Deviations) || !reflect.DeepEqual(got.Discrepancies, want.Discrepancies) || got.Notes != want.Notes {
		line("deviations, discrepancies or notes differ")
	}
	if len(got.HashChecks) != len(want.HashChecks) {
		line("hash_checks: %d entries, regenerated %d", len(got.HashChecks), len(want.HashChecks))
	}
	for i := 0; i < len(got.HashChecks) && i < len(want.HashChecks); i++ {
		if !reflect.DeepEqual(got.HashChecks[i], want.HashChecks[i]) {
			line("hash_checks[%d] %q differs", i, want.HashChecks[i].Name)
		}
	}
	if len(got.Trees) != len(want.Trees) {
		line("trees: %d entries, regenerated %d", len(got.Trees), len(want.Trees))
	}
	for i := 0; i < len(got.Trees) && i < len(want.Trees); i++ {
		if !reflect.DeepEqual(got.Trees[i], want.Trees[i]) {
			line("trees[%d] %q differs", i, want.Trees[i].Name)
		}
	}
	if len(got.Inclusion) != len(want.Inclusion) {
		line("inclusion: %d entries, regenerated %d", len(got.Inclusion), len(want.Inclusion))
	}
	for i := 0; i < len(got.Inclusion) && i < len(want.Inclusion); i++ {
		if !reflect.DeepEqual(got.Inclusion[i], want.Inclusion[i]) {
			line("inclusion[%d] %q differs", i, want.Inclusion[i].Name)
		}
	}
	if shown == 0 {
		line("formatting differs (the decoded content is equal)")
	}
	if shown > 20 {
		failf("fixtures", "differs from the regenerated fixture in %d more places", shown-20)
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

const usage = `usage: go run . -fixtures <path> [-write] [-ours <path>]

  -fixtures <path>  fixture file to check, and to write with -write (required)
  -write            regenerate the fixture file, then check it
  -ours <path>      also check truestamp_merkle's vectors/merkle.json with
                    the module's own functions

In the truestamp_merkle repository, from interop/go/codenotary-merkletree/:

  go run . -fixtures ../../../vectors/interop/codenotary-merkletree.json -write
`

var flatten = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")

// failf prints one FAIL line for a phase: "FAIL usage: ..." for the command
// line, "FAIL fixtures ..." and "FAIL ours ..." for the two checks. Line
// breaks inside the message become spaces, so a problem is always one line.
func failf(phase, format string, a ...interface{}) {
	msg := flatten.Replace(fmt.Sprintf(format, a...))
	if phase == "usage" {
		fmt.Println("FAIL usage: " + msg)
		return
	}
	fmt.Println("FAIL " + phase + " " + msg)
}

// guard runs one phase and turns a panic in it into one FAIL line.
func guard(phase string, fn func() bool) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			failf(phase, "internal error: %v", r)
			ok = false
		}
	}()
	return fn()
}

// pathFlag is a path flag that must be given once, with a non-empty value
// that is not itself a flag.
type pathFlag struct {
	value string
	set   bool
}

func (p *pathFlag) String() string {
	if p == nil {
		return ""
	}
	return p.value
}

func (p *pathFlag) Set(s string) error {
	switch {
	case p.set:
		return errors.New("given more than once")
	case s == "":
		return errors.New("needs a non-empty path")
	case strings.HasPrefix(s, "-"):
		return errors.New("needs a path, not a flag (write ./-name for a file whose name starts with -)")
	}
	p.value, p.set = s, true
	return nil
}

// onceBool is a boolean flag that may be given once.
type onceBool struct {
	value, set bool
}

func (b *onceBool) IsBoolFlag() bool { return true }

func (b *onceBool) String() string {
	if b == nil {
		return "false"
	}
	return strconv.FormatBool(b.value)
}

func (b *onceBool) Set(s string) error {
	if b.set {
		return errors.New("given more than once")
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return errors.New("not a boolean")
	}
	b.value, b.set = v, true
	return nil
}

type options struct {
	fixtures, ours pathFlag
	write          onceBool
}

// parseArgs reads the command line. done is true when the program should
// exit with status at once: 0 after -h, 1 after one "FAIL usage: ..." line.
func parseArgs(args []string) (opts options, status int, done bool) {
	fs := flag.NewFlagSet("codenotary-merkletree", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.Var(&opts.fixtures, "fixtures", "fixture file to check (and to write with -write); required")
	fs.Var(&opts.write, "write", "regenerate the fixture file, then check it")
	fs.Var(&opts.ours, "ours", "truestamp_merkle vectors/merkle.json to check with the module's functions")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(os.Stderr, usage)
			return opts, 0, true
		}
		failf("usage", "%v", err)
		return opts, 1, true
	}
	if fs.NArg() > 0 {
		failf("usage", "unexpected argument %q (every input is a flag)", fs.Arg(0))
		return opts, 1, true
	}
	if !opts.fixtures.set {
		failf("usage", "-fixtures <path> is required")
		return opts, 1, true
	}
	return opts, 0, false
}

// run parses the arguments, checks the fixture and, with -ours, the
// library's vectors, and returns the exit status: 0 when everything holds,
// 1 on any failure. It never returns 2 and never lets a panic escape.
func run(args []string) int {
	var opts options
	status, done := 1, true
	if !guard("usage", func() bool {
		opts, status, done = parseArgs(args)
		return true
	}) {
		return 1
	}
	if done {
		return status
	}
	ok := guard("fixtures", func() bool { return checkFixture(opts.fixtures.value, opts.write.value) })
	if opts.ours.set {
		if !guard("ours", func() bool { return checkOurs(opts.ours.value) }) {
			ok = false
		}
	}
	if !ok {
		return 1
	}
	return 0
}

// checkFixture builds the fixture, writes it first with -write, and checks
// the file, printing one OK line or FAIL lines.
func checkFixture(path string, write bool) bool {
	f, st, err := build()
	if err != nil {
		failf("fixtures", "build: %v", err)
		return false
	}
	want, err := encode(f)
	if err != nil {
		failf("fixtures", "encode: %v", err)
		return false
	}
	if write {
		if len(want) > sizeBudget {
			failf("fixtures", "regenerated fixture is %d bytes, over the %d byte budget", len(want), sizeBudget)
			return false
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			failf("fixtures", "write: %v", err)
			return false
		}
	}
	return check(path, want, f, st)
}
