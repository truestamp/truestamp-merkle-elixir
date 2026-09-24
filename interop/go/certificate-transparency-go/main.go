// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains short literals from github.com/google/certificate-transparency-go@v1.0.16
// (Apache-2.0, Copyright 2014 and 2016 Google Inc. All Rights Reserved.): the
// t.Fatal labels of merkletree/merkle_verifier_test.go:356-379, the upstream
// line numbers and names cited in fixture text, and the procedure of
// scanner/scanner_test_data.go:360-400 (makeParent, CalcRootHash) restated to
// explain a deviation. License: LICENSE-certificate-transparency-go in this
// directory.

// This program regenerates and checks the truestamp_merkle library's fixture
// for github.com/google/certificate-transparency-go v1.0.16, the last release
// that shipped its own RFC 6962 Merkle code (package merkletree). It lives at
// interop/go/certificate-transparency-go/ in the library, and the fixture at
// vectors/interop/certificate-transparency-go.json.
//
// Every published value comes out of upstream code that upstream_vectors.go
// holds byte for byte (verified at run time against vendored copies of the
// upstream files, whose SHA-256 values are pinned below), and every verdict
// comes from the module's own merkletree.MerkleVerifier.
//
//	go run . -fixtures <path>          check the fixture
//	go run . -fixtures <path> -write   regenerate the fixture, then check it
//	go run . -fixtures <path> -ours <path to the library's vectors/merkle.json>
//	                                   also check the library's own vectors (ours.go)
//
// -fixtures is required. On success the program prints one line
// "OK fixtures github.com/google/certificate-transparency-go@v1.0.16: <counts>"
// and, with -ours, a second line "OK ours <same>: <counts>", and exits 0.
// Otherwise it prints one "FAIL fixtures ..." or "FAIL ours ..." line per
// problem and exits 1. A bad command line (an unknown flag, a missing or empty
// value, a stray argument) prints the single line "FAIL usage: <reason>" and
// exits 1; -h prints the usage to stderr and exits 0. Apart from the -fixtures
// and -ours paths it reads only files inside its own module directory.
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/merkletree"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/testdata"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509util"
)

const (
	modulePath    = "github.com/google/certificate-transparency-go"
	moduleVersion = "v1.0.16"
	verifierFile  = "merkletree/merkle_verifier_test.go"
)

func sha256Fn(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// The module's own hasher and verifier. Nothing in this program hashes a tree
// node or checks a proof except through these two values.
var (
	hasher       = merkletree.NewTreeHasher(sha256Fn)
	realVerifier = merkletree.NewMerkleVerifier(sha256Fn)
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

// ---------------------------------------------------------------------------
// Verbatim upstream blocks
// ---------------------------------------------------------------------------

//go:embed upstream_vectors.go
var upstreamSrc string

const upstreamSrcName = "upstream_vectors.go"

type block struct {
	file        string
	first, last int // upstream line range, 1-based, inclusive
	myFirst     int // line in upstream_vectors.go holding upstream line `first`
	lines       []string
}

var (
	blocks  []block
	beginRe = regexp.MustCompile(`^\t*// BEGIN (\S+):(\d+)-(\d+)$`)
	endRe   = regexp.MustCompile(`^\t*// END$`)
)

// parseBlocks reads the verbatim blocks of upstream_vectors.go. A BEGIN marker
// (indented as gofmt places it) names the upstream line range, so the block is
// exactly the next last-first+1 lines; after it, and after any blank lines
// gofmt puts before a top-level comment, must come the END marker.
func parseBlocks() error {
	lines := strings.Split(upstreamSrc, "\n")
	for i := 0; i < len(lines); i++ {
		m := beginRe.FindStringSubmatch(lines[i])
		if m == nil {
			if strings.Contains(lines[i], "// BEGIN ") || endRe.MatchString(lines[i]) {
				return fmt.Errorf("%s line %d: a marker outside the BEGIN/END pairing", upstreamSrcName, i+1)
			}
			continue
		}
		first, e1 := strconv.Atoi(m[2])
		last, e2 := strconv.Atoi(m[3])
		if e1 != nil || e2 != nil || first < 1 || last < first {
			return fmt.Errorf("%s line %d: bad range in BEGIN marker", upstreamSrcName, i+1)
		}
		n := last - first + 1
		if i+1+n > len(lines) {
			return fmt.Errorf("%s: block %s:%d-%d runs past the end of the file", upstreamSrcName, m[1], first, last)
		}
		b := block{file: m[1], first: first, last: last, myFirst: i + 2, lines: lines[i+1 : i+1+n]}
		for _, l := range b.lines {
			if beginRe.MatchString(l) || endRe.MatchString(l) {
				return fmt.Errorf("%s: block %s:%d-%d holds a marker line", upstreamSrcName, b.file, first, last)
			}
		}
		j := i + 1 + n
		for j < len(lines) && lines[j] == "" {
			j++
		}
		if j == len(lines) || !endRe.MatchString(lines[j]) {
			return fmt.Errorf("%s: block %s:%d-%d is not followed by an END marker", upstreamSrcName, b.file, first, last)
		}
		blocks = append(blocks, b)
		i = j
	}
	if len(blocks) != 6 {
		return fmt.Errorf("%s holds %d verbatim blocks, want 6", upstreamSrcName, len(blocks))
	}
	return nil
}

// checkBlocks compares every block byte for byte with the vendored copy of
// the module's file.
func checkBlocks(moduleDir string) error {
	for _, b := range blocks {
		raw, err := os.ReadFile(filepath.Join(moduleDir, b.file))
		if err != nil {
			return err
		}
		up := strings.Split(string(raw), "\n")
		if b.last > len(up) {
			return fmt.Errorf("%s has only %d lines, block wants %d-%d", b.file, len(up), b.first, b.last)
		}
		for k, got := range b.lines {
			if want := up[b.first-1+k]; got != want {
				return fmt.Errorf("%s line %d differs from %s:%d: upstream %q, here %q",
					upstreamSrcName, b.myFirst+k, b.file, b.first+k, want, got)
			}
		}
	}
	return nil
}

// callerUpstream maps a stack frame inside a verbatim block to its upstream
// file and line. skip=1 is the caller of the function that calls this.
func callerUpstream(skip int) (string, int) {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok || filepath.Base(file) != upstreamSrcName {
		return "", 0
	}
	for _, b := range blocks {
		if line >= b.myFirst && line < b.myFirst+len(b.lines) {
			return b.file, b.first + (line - b.myFirst)
		}
	}
	return "", 0
}

// ---------------------------------------------------------------------------
// Recording verifier used by the verbatim upstream test code
// ---------------------------------------------------------------------------

type fatalPanic struct{}

type fakeT struct{ failures []string }

func (t *fakeT) Fatal(args ...interface{}) {
	t.failures = append(t.failures, fmt.Sprint(args...))
	panic(fatalPanic{})
}

func (t *fakeT) Fatalf(format string, args ...interface{}) {
	t.failures = append(t.failures, fmt.Sprintf(format, args...))
	panic(fatalPanic{})
}

func runUpstream(f func(*fakeT)) []string {
	t := &fakeT{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(fatalPanic); !ok {
					panic(r)
				}
			}
		}()
		f(t)
	}()
	return t.failures
}

type recGroup struct {
	callerLine int // upstream line that called verifierCheck
	seq        int // occurrence of that caller line, 0-based
	leafIndex  int64
	treeSize   int64
}

type recCall struct {
	line       int // upstream line of the VerifyInclusionProof call
	group      int // index into recGroups, or -1 for a direct call
	modifyIdx  int // proof index for the verifierCheck line-82 loop
	leafIndex  int64
	treeSize   int64
	proof      [][]byte
	root, leaf []byte
	accepted   bool
}

var (
	recGroups []recGroup
	recCalls  []recCall
	recErrs   []string
)

// MerkleVerifier stands in for merkletree.MerkleVerifier inside the verbatim
// upstream code: it delegates to the module's verifier and records each call.
type MerkleVerifier struct{}

func getVerifier() MerkleVerifier { return MerkleVerifier{} }

func (MerkleVerifier) RootFromInclusionProof(leafIndex, treeSize int64, proof [][]byte, leaf []byte) ([]byte, error) {
	file, line := callerUpstream(1)
	cfile, cline := callerUpstream(2)
	if file == verifierFile && line == 36 && cfile == verifierFile {
		seq := 0
		for _, g := range recGroups {
			if g.callerLine == cline {
				seq++
			}
		}
		recGroups = append(recGroups, recGroup{callerLine: cline, seq: seq, leafIndex: leafIndex, treeSize: treeSize})
	} else {
		recErrs = append(recErrs, fmt.Sprintf("unexpected RootFromInclusionProof caller %s:%d", file, line))
	}
	return realVerifier.RootFromInclusionProof(leafIndex, treeSize, proof, leaf)
}

func (MerkleVerifier) VerifyInclusionProof(leafIndex, treeSize int64, proof [][]byte, root []byte, leaf []byte) error {
	err := realVerifier.VerifyInclusionProof(leafIndex, treeSize, proof, root, leaf)
	// The same question asked at the leaf-hash level must get the same answer.
	errByHash := realVerifier.VerifyInclusionProofByHash(leafIndex, treeSize, proof, root, hasher.HashLeaf(leaf))
	file, line := callerUpstream(1)
	if file != verifierFile {
		recErrs = append(recErrs, fmt.Sprintf("unexpected VerifyInclusionProof caller %s:%d", file, line))
	}
	if (err == nil) != (errByHash == nil) {
		recErrs = append(recErrs, fmt.Sprintf("line %d: VerifyInclusionProof=%v but VerifyInclusionProofByHash=%v", line, err, errByHash))
	}
	c := recCall{line: line, group: -1, modifyIdx: -1, leafIndex: leafIndex, treeSize: treeSize,
		proof: cloneProof(proof), root: clone(root), leaf: clone(leaf), accepted: err == nil}
	if line >= 34 && line <= 119 { // inside verifierCheck
		c.group = len(recGroups) - 1
		if line == 82 {
			n := 0
			for _, p := range recCalls {
				if p.group == c.group && p.line == 82 {
					n++
				}
			}
			c.modifyIdx = n
		}
	}
	recCalls = append(recCalls, c)
	return err
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}

func cloneProof(p [][]byte) [][]byte {
	out := make([][]byte, len(p))
	for i := range p {
		out[i] = clone(p[i])
	}
	return out
}

// Labels for the VerifyInclusionProof calls in verifierCheck
// (merkle_verifier_test.go:34-119), keyed by upstream line.
var verifierCheckLabels = map[int]string{
	43:  "known good proof",
	48:  "corrupted: leafIndex - 1",
	51:  "corrupted: leafIndex + 1",
	54:  "corrupted: leafIndex ^ 2",
	59:  "corrupted: treeSize * 2",
	62:  "corrupted: treeSize / 2",
	67:  "corrupted: leaf data replaced by 'WrongLeaf'",
	72:  "corrupted: root replaced by the empty tree hash",
	82:  "corrupted: proof[%d] replaced by the empty tree hash",
	90:  "corrupted: trailing garbage (zero-length element appended)",
	95:  "corrupted: trailing root (root appended to the proof)",
	102: "corrupted: truncated proof (last element removed)",
	109: "corrupted: preceding garbage (zero-length element prepended)",
	114: "corrupted: preceding root (root prepended to the proof)",
}

// Labels for the direct calls in TestVerifyInclusionProof, from the upstream
// t.Fatal messages ("Incorrectly verified invalid path 1", ...).
var directLabels = map[int]string{
	356: "invalid path 1", 359: "invalid path 2", 362: "invalid path 3", 365: "invalid path 4",
	369: "invalid root 1", 372: "invalid root 2", 375: "invalid root 3", 378: "invalid root 4",
}

func groupLabel(g recGroup) (string, error) {
	switch g.callerLine {
	case 347:
		return "TestVerifyInclusionProofTreeSizeOne (merkle_verifier_test.go:347, real CT instance, leaf = test-cert.pem MerkleTreeLeaf)", nil
	case 394:
		// The upstream loop runs i = 1..5 over getInclusionTestVector().
		return fmt.Sprintf("TestVerifyInclusionProof getInclusionTestVector()[%d] (merkle_verifier_test.go:394)", g.seq+1), nil
	}
	return "", fmt.Errorf("verifierCheck called from unexpected line %d", g.callerLine)
}

// ---------------------------------------------------------------------------
// RFC 9162 section 2.1 over the module's hasher (the module has no tree
// builder or prover: MerkleTreeInterface is declared but never implemented)
// ---------------------------------------------------------------------------

func splitPoint(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// rfcMTH is MTH(D[n]) of RFC 9162 section 2.1.1 at the leaf-hash level.
func rfcMTH(leafHashes [][]byte) []byte {
	switch n := len(leafHashes); n {
	case 0:
		return hasher.HashEmpty()
	case 1:
		return leafHashes[0]
	default:
		k := splitPoint(n)
		return hasher.HashChildren(rfcMTH(leafHashes[:k]), rfcMTH(leafHashes[k:]))
	}
}

// rfcPath is PATH(m, D[n]) of RFC 9162 section 2.1.3.1, bottom to top.
func rfcPath(leafHashes [][]byte, m int) [][]byte {
	n := len(leafHashes)
	if n <= 1 {
		return [][]byte{}
	}
	k := splitPoint(n)
	if m < k {
		return append(rfcPath(leafHashes[:k], m), rfcMTH(leafHashes[k:]))
	}
	return append(rfcPath(leafHashes[k:], m-k), rfcMTH(leafHashes[:k]))
}

// rfcVerify is RFC 9162 section 2.1.3.2, written from the RFC text, hashing
// only through the module's HashChildren. It gives the RFC answer that a case
// carries in rfc9162_valid when the module's verifier disagrees.
func rfcVerify(leafIndex, treeSize int64, leafHash []byte, path [][]byte, root []byte) bool {
	if leafIndex < 0 || treeSize < 0 || leafIndex >= treeSize {
		return false
	}
	fn, sn := leafIndex, treeSize-1
	r := leafHash
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = hasher.HashChildren(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = hasher.HashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

func rfcVerifyCase(c Inclusion) (bool, error) {
	leaf, e1 := unhex(c.LeafHash)
	path, e2 := unhexList(c.Path)
	root, e3 := unhex(c.Root)
	if e1 != nil || e2 != nil || e3 != nil {
		return false, fmt.Errorf("inclusion %q: bad hex", c.Name)
	}
	return rfcVerify(c.LeafIndex, c.TreeSize, leaf, path, root), nil
}

func rfcDisagreement(c Inclusion) string {
	return fmt.Sprintf("%s: the module's MerkleVerifier returns valid=%v, RFC 9162 section 2.1.3.2 gives %v", c.Name, c.Valid, *c.RFC9162Valid)
}

// ---------------------------------------------------------------------------
// scanner/scanner_test_data.go FourEntrySTH: a hard-coded tree_size 4 root
// that is NOT an RFC 6962/9162 root, examined with the module's own code so
// the notes and deviations can say why it is not a known answer here.
// ---------------------------------------------------------------------------

type fourEntrySTH struct {
	sthRootB64       string
	sthRoot, rfcRoot []byte
}

func scannerFourEntry() (*fourEntrySTH, error) {
	var sth struct {
		TreeSize int64  `json:"tree_size"`
		Root     string `json:"sha256_root_hash"`
	}
	if err := json.Unmarshal([]byte(scanner.FourEntrySTH), &sth); err != nil {
		return nil, fmt.Errorf("scanner.FourEntrySTH: %v", err)
	}
	sthRoot, err := base64.StdEncoding.DecodeString(sth.Root)
	if err != nil || sth.TreeSize != 4 || len(sthRoot) != 32 {
		return nil, fmt.Errorf("scanner.FourEntrySTH: tree_size %d, root %q: %v", sth.TreeSize, sth.Root, err)
	}

	// CalcRootHash (scanner_test_data.go:373-400) logs the root it computes.
	var buf bytes.Buffer
	prevOut, prevFlags, prevPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	scanner.CalcRootHash()
	log.SetOutput(prevOut)
	log.SetFlags(prevFlags)
	log.SetPrefix(prevPrefix)
	if got := strings.TrimSpace(buf.String()); got != sth.Root {
		return nil, fmt.Errorf("scanner.CalcRootHash() logged %q, FourEntrySTH has %q", got, sth.Root)
	}

	// FourEntries (lines 28-264) serves Entry0..Entry3 (lines 266-357).
	entries := []string{scanner.Entry0, scanner.Entry1, scanner.Entry2, scanner.Entry3}
	var fe struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(scanner.FourEntries), &fe); err != nil || len(fe.Entries) != len(entries) {
		return nil, fmt.Errorf("scanner.FourEntries: %d entries, %v", len(fe.Entries), err)
	}
	var data, lh [][]byte
	for i, e := range entries {
		if fe.Entries[i].LeafInput != e {
			return nil, fmt.Errorf("scanner.FourEntries[%d].leaf_input != Entry%d", i, i)
		}
		d, err := base64.StdEncoding.DecodeString(e)
		if err != nil {
			return nil, err
		}
		data = append(data, d)
		lh = append(lh, hasher.HashLeaf(d))
	}

	// The helper's procedure as the notes describe it: leaves SHA-256(entry)
	// with no prefix; a parent is SHA-256 of 64 bytes holding the first 31
	// bytes of each child, each followed by one zero byte, with no prefix.
	parent := func(a, b []byte) []byte {
		r := make([]byte, 64)
		copy(r[0:31], a)
		copy(r[32:63], b)
		return sha256Fn(r)
	}
	var h [][]byte
	for _, d := range data {
		h = append(h, sha256Fn(d))
	}
	if described := parent(parent(h[0], h[1]), parent(h[2], h[3])); !bytes.Equal(described, sthRoot) {
		return nil, errors.New("the described CalcRootHash procedure does not give the FourEntrySTH root")
	}

	// RFC 9162 over the module's hasher, and the module's own verifier.
	rfcRoot := rfcMTH(lh)
	if bytes.Equal(rfcRoot, sthRoot) {
		return nil, errors.New("FourEntrySTH root equals the RFC 9162 MTH, the notes would be wrong")
	}
	for m := range lh {
		p := rfcPath(lh, m)
		if realVerifier.VerifyInclusionProofByHash(int64(m), 4, p, rfcRoot, lh[m]) != nil {
			return nil, fmt.Errorf("module verifier rejects FourEntries leaf %d against the RFC 9162 root", m)
		}
		if realVerifier.VerifyInclusionProofByHash(int64(m), 4, p, sthRoot, lh[m]) == nil {
			return nil, fmt.Errorf("module verifier accepts FourEntries leaf %d against the FourEntrySTH root", m)
		}
	}
	return &fourEntrySTH{sthRootB64: sth.Root, sthRoot: sthRoot, rfcRoot: rfcRoot}, nil
}

func fourEntryDeviation(fs *fourEntrySTH) string {
	return fmt.Sprintf("Not the merkletree code under test, and not used as a known answer: scanner/scanner_test_data.go:23-27 hard-codes FourEntrySTH, tree_size 4 with sha256_root_hash %s (hex %s), over Entry0..Entry3 (lines 266-357, also served as FourEntries, lines 28-264). That root comes from the scanner package's test-data helper CalcRootHash (lines 373-400, makeParent at 360-371), which is not RFC 6962/9162: each leaf is SHA-256(entry) with no 0x00 prefix, and each parent is SHA-256 of a 64-byte buffer that holds only the first 31 bytes of each child (makeParent copies into r[0:31] and r[32:63], leaving bytes 31 and 63 zero), with no 0x01 prefix. The RFC 9162 MTH of the same four entries is %s. The interop program reproduces %s by calling scanner.CalcRootHash and by the procedure just described, and the module's own merkletree verifier accepts all four leaves against %s and rejects all four against %s, so the fixture deliberately leaves the value out.",
		fs.sthRootB64, hx(fs.sthRoot), hx(fs.rfcRoot), hx(fs.sthRoot), hx(fs.rfcRoot), hx(fs.sthRoot))
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

func hx(b []byte) string { return hex.EncodeToString(b) }

func hexList(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = hx(b)
	}
	return out
}

func strp(s string) *string { return &s }

func rfcSentence(st *genStats) string {
	if st.rfcAgree == st.cases {
		return "no case carries rfc9162_valid."
	}
	return strconv.Itoa(st.cases-st.rfcAgree) + " cases carry rfc9162_valid and are listed under discrepancies."
}

type genStats struct {
	blocks          int
	consistencyOK   int
	consistencyAll  int
	consistencySize map[int64]bool
	testCertLeafLen int
	precertLeafLen  int
	four            *fourEntrySTH
	rfcAgree, cases int
}

// The upstream files this program reads at run time are vendored, byte for
// byte from the github.com/google/certificate-transparency-go@v1.0.16 module
// zip (Apache-2.0, license text included), under this directory of the
// program's own module. The go tool ignores testdata directories, so the
// vendored _test.go files are never compiled. Each file's SHA-256 is pinned
// here; to re-confirm a copy against the module cache, compare it with
// $(go env GOMODCACHE)/github.com/google/certificate-transparency-go@v1.0.16/<path>.
const vendoredRel = "testdata/certificate-transparency-go@v1.0.16"

var vendoredSHA256 = map[string]string{
	"LICENSE":                            "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
	"merkletree/merkle_verifier_test.go": "9584002124ea3e47877bfb3e519b095fd8e4c81777d717852afada4383572a81",
	"merkletree/tree_hasher_test.go":     "4019c33dc08d095af24d11f4e78dd49627e99fda96f85b2c9ceab04b9efab7f3",
	"serialization_test.go":              "38b3fc051f3c30be8ac0fcd131d2cefba57ed3dc2043932fe97857f08b7a4fb3",
	"testdata/test-cert.pem":             "83376a1110a8af81a15ab362f3299b28e32342f5bce3a754229248c8cb96386c",
	"testdata/test-cert.proof":           "93469170a217dd36cdd5b1d53eb0857de5a7d7fdc1abe55b229d951dfe570518",
}

// selfDir is this program's module directory: the directory of this source
// file when the build recorded an absolute path, otherwise the working
// directory (go run . runs from the module directory).
func selfDir() (string, error) {
	if _, file, _, ok := runtime.Caller(0); ok && filepath.IsAbs(file) {
		dir := filepath.Dir(file)
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
	}
	return os.Getwd()
}

// vendoredDir returns the vendored upstream tree after checking every pinned
// file's SHA-256.
func vendoredDir() (string, error) {
	self, err := selfDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(self, filepath.FromSlash(vendoredRel))
	for rel, want := range vendoredSHA256 {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return "", fmt.Errorf("vendored upstream file: %v", err)
		}
		if got := hx(sha256Fn(b)); got != want {
			return "", fmt.Errorf("vendored %s/%s has SHA-256 %s, pinned %s", vendoredRel, rel, got, want)
		}
	}
	return dir, nil
}

func linkedVersionOK() error {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("no build info")
	}
	for _, d := range bi.Deps {
		if d.Path == modulePath {
			if d.Version != moduleVersion || d.Replace != nil {
				return fmt.Errorf("linked %s %s (replace %v), want %s", modulePath, d.Version, d.Replace, moduleVersion)
			}
			return nil
		}
	}
	return fmt.Errorf("%s not linked", modulePath)
}

// runInclusionTests runs the two verbatim upstream inclusion test bodies from
// the vendored merkletree directory: the TreeSizeOne body reads
// ../testdata/test-cert.pem and .proof, which resolve to the vendored copies
// from there. The working directory is restored even if a body panics.
func runInclusionTests(modDir string) (fail1, fail2 []string, err error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chdir(filepath.Join(modDir, "merkletree")); err != nil {
		return nil, nil, err
	}
	defer func() {
		if cerr := os.Chdir(wd); cerr != nil && err == nil {
			err = cerr
		}
	}()
	fail1 = runUpstream(testVerifyInclusionProofTreeSizeOne)
	fail2 = runUpstream(testVerifyInclusionProof)
	return fail1, fail2, nil
}

func generate(modDir string) (*Fixture, *genStats, error) {
	st := &genStats{consistencySize: map[int64]bool{}}
	if err := parseBlocks(); err != nil {
		return nil, nil, err
	}
	if err := checkBlocks(modDir); err != nil {
		return nil, nil, err
	}
	st.blocks = len(blocks)

	// Run the two upstream inclusion tests verbatim, recording every call.
	fail1, fail2, err := runInclusionTests(modDir)
	if err != nil {
		return nil, nil, err
	}
	if len(fail1)+len(fail2) > 0 {
		return nil, nil, fmt.Errorf("upstream test bodies failed against the module: %v %v", fail1, fail2)
	}
	if len(recErrs) > 0 {
		return nil, nil, fmt.Errorf("recording: %s", strings.Join(recErrs, "; "))
	}
	if len(recGroups) != 6 {
		return nil, nil, fmt.Errorf("verifierCheck ran %d times, want 6", len(recGroups))
	}

	tv := getTestVector()
	inputs := getInputs()
	roots := getRoots()
	testCertLeaf := upstreamTestCertLeafBytes()
	st.testCertLeafLen = len(testCertLeaf)

	// ---- empty root
	if !bytes.Equal(tv.emptyHash, hasher.HashEmpty()) || !bytes.Equal(dh(sha256EmptyTreeHash), hasher.HashEmpty()) {
		return nil, nil, errors.New("HashEmpty() does not reproduce the published empty hash")
	}
	emptyRoot := hx(tv.emptyHash)

	// ---- hash checks
	var hcs []HashCheck
	for i, l := range tv.leaves {
		if int64(len(l.input)) != l.inputLength {
			return nil, nil, fmt.Errorf("getTestVector leaf %d: length %d != %d", i, len(l.input), l.inputLength)
		}
		if !bytes.Equal(hasher.HashLeaf(l.input), l.output) {
			return nil, nil, fmt.Errorf("HashLeaf does not reproduce getTestVector leaf %d", i)
		}
		hcs = append(hcs, HashCheck{
			Name:     fmt.Sprintf("tree_hasher_test.go:%d getTestVector().leaves[%d] (%d-byte input)", 59+i, i, l.inputLength),
			Kind:     "leaf",
			InputHex: strp(hx(l.input)),
			Hash:     hx(l.output),
		})
	}
	for i, nd := range tv.nodes {
		if !bytes.Equal(hasher.HashChildren(nd.left, nd.right), nd.output) {
			return nil, nil, fmt.Errorf("HashChildren does not reproduce getTestVector node %d", i)
		}
		hcs = append(hcs, HashCheck{
			Name:  fmt.Sprintf("tree_hasher_test.go:64-66 getTestVector().nodes[%d]", i),
			Kind:  "node",
			Left:  strp(hx(nd.left)),
			Right: strp(hx(nd.right)),
			Hash:  hx(nd.output),
		})
	}

	// test-cert leaf: literal leaf bytes (serialization_test.go:383) and the
	// literal leaf hash (testdata/certs.go:396, also the root at
	// merkle_verifier_test.go:347).
	certHash, err := base64.StdEncoding.DecodeString(testdata.TestCertB64LeafHash)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(hasher.HashLeaf(testCertLeaf), certHash) {
		return nil, nil, errors.New("HashLeaf(test-cert leaf) != TestCertB64LeafHash")
	}
	if err := confirmCertLeaf(modDir, testCertLeaf, certHash); err != nil {
		return nil, nil, err
	}
	hcs = append(hcs, HashCheck{
		Name:     "serialization_test.go:383 serialized X509 MerkleTreeLeaf of testdata/test-cert.pem; hash = testdata/certs.go:396 TestCertB64LeafHash (ctutil_test.go:35-40 'cert'; merkle_verifier_test.go:347 size-1 root)",
		Kind:     "leaf",
		InputHex: strp(hx(testCertLeaf)),
		Hash:     hx(certHash),
	})

	// precert leaf: literal leaf hash (testdata/certs.go:400); the leaf bytes
	// have no upstream hex literal and are built by the module from the
	// upstream PEM and SCT literals, exactly as ctutil.LeafHash does.
	preLeaf, preHash, err := precertLeaf()
	if err != nil {
		return nil, nil, err
	}
	st.precertLeafLen = len(preLeaf)
	hcs = append(hcs, HashCheck{
		Name:     "ctutil_test.go:41-53 'precert' and 'cert with embedded SCT'; hash = testdata/certs.go:400 TestPreCertB64LeafHash; input = tls.Marshal(ct.MerkleTreeLeafFromChain(TestPreCertPEM+CACertPEM, precert, TestPreCertProof timestamp)) built by the module (no upstream hex literal for this input)",
		Kind:     "leaf",
		InputHex: strp(hx(preLeaf)),
		Hash:     hx(preHash),
	})

	// ---- trees
	var trees []Tree
	for k := 1; k <= len(roots); k++ {
		var data, lh [][]byte
		for i := 0; i < k; i++ {
			if len(inputs[i].h) != inputs[i].l {
				return nil, nil, fmt.Errorf("getInputs()[%d] length mismatch", i)
			}
			data = append(data, inputs[i].h)
			lh = append(lh, hasher.HashLeaf(inputs[i].h))
		}
		root := roots[k-1].h
		if !bytes.Equal(rfcMTH(lh), root) {
			return nil, nil, fmt.Errorf("RFC 9162 MTH over the module's hasher does not give getRoots()[%d]", k-1)
		}
		trees = append(trees, Tree{
			Name:       fmt.Sprintf("merkle_verifier_test.go:%d getRoots()[%d]: MTH of the first %d getInputs() leaves (lines 231-%d)", 279+k-1, k-1, k, 230+k),
			LeafData:   hexList(data),
			LeafHashes: hexList(lh),
			TreeSize:   int64(k),
			Root:       hx(root),
		})
	}
	// The real-CT size-1 tree: root is the one TestVerifyInclusionProofTreeSizeOne
	// passes to verifierCheck (recorded from the verbatim call).
	var tsoRoot []byte
	for _, c := range recCalls {
		if c.group == 0 && c.line == 43 {
			tsoRoot = c.root
			if !bytes.Equal(c.leaf, testCertLeaf) {
				return nil, nil, errors.New("TestVerifyInclusionProofTreeSizeOne leaf (from test-cert.pem/.proof) != serialization_test.go:383 literal")
			}
		}
	}
	if tsoRoot == nil || !bytes.Equal(tsoRoot, certHash) {
		return nil, nil, errors.New("size-1 root not recorded or != TestCertB64LeafHash")
	}
	trees = append(trees, Tree{
		Name:       "merkle_verifier_test.go:321-350 TestVerifyInclusionProofTreeSizeOne: 1-leaf tree from a real CT instance, leaf = serialized MerkleTreeLeaf of testdata/test-cert.pem (serialization_test.go:383), root at line 347",
		LeafData:   []string{hx(testCertLeaf)},
		LeafHashes: []string{hx(hasher.HashLeaf(testCertLeaf))},
		TreeSize:   1,
		Root:       hx(tsoRoot),
	})

	// ---- published inclusion cases, in upstream call order
	var incs []Inclusion
	for _, c := range recCalls {
		var name, expect string
		if c.group >= 0 {
			g := recGroups[c.group]
			gl, err := groupLabel(g)
			if err != nil {
				return nil, nil, err
			}
			lbl, ok := verifierCheckLabels[c.line]
			if !ok {
				return nil, nil, fmt.Errorf("no label for verifierCheck line %d", c.line)
			}
			if c.line == 82 {
				lbl = fmt.Sprintf(lbl, c.modifyIdx)
			}
			name = fmt.Sprintf("%s, leaf index %d, tree size %d: %s (verifierCheck, merkle_verifier_test.go:%d)", gl, g.leafIndex, g.treeSize, lbl, c.line)
			expect = "invalid"
			if c.line == 43 {
				expect = "valid"
			}
		} else {
			lbl, ok := directLabels[c.line]
			if !ok {
				return nil, nil, fmt.Errorf("no label for direct call at line %d", c.line)
			}
			name = fmt.Sprintf("TestVerifyInclusionProof: %s (merkle_verifier_test.go:%d)", lbl, c.line)
			expect = "invalid"
		}
		incs = append(incs, Inclusion{
			Name:                name,
			LeafHash:            hx(hasher.HashLeaf(c.leaf)),
			LeafIndex:           c.leafIndex,
			TreeSize:            c.treeSize,
			Path:                hexList(c.proof),
			Root:                hx(c.root),
			Valid:               c.accepted,
			UpstreamExpectation: expect,
		})
	}

	// ---- generated inclusion cases: every (m, n) for n = 1..8 over getInputs()
	for n := 1; n <= len(roots); n++ {
		var lh [][]byte
		for i := 0; i < n; i++ {
			lh = append(lh, hasher.HashLeaf(inputs[i].h))
		}
		root := roots[n-1].h
		for m := 0; m < n; m++ {
			p := rfcPath(lh, m)
			ok := realVerifier.VerifyInclusionProofByHash(int64(m), int64(n), p, root, lh[m]) == nil
			if !ok {
				return nil, nil, fmt.Errorf("module verifier rejects generated proof m=%d n=%d", m, n)
			}
			incs = append(incs, Inclusion{
				Name:                fmt.Sprintf("generated: RFC 9162 PATH(%d, D[0:%d]) over getInputs(), root getRoots()[%d]", m, n, n-1),
				LeafHash:            hx(lh[m]),
				LeafIndex:           int64(m),
				TreeSize:            int64(n),
				Path:                hexList(p),
				Root:                hx(root),
				Valid:               ok,
				UpstreamExpectation: "none",
			})
		}
	}

	// ---- consistency proofs (not in the schema): the module's
	// VerifyConsistencyProof over getConsistencyProofs() and getRoots(), as in
	// merkle_verifier_test.go:459-475, as extra confirmation of those roots.
	for _, cp := range getConsistencyProofs() {
		st.consistencyAll++
		proof := [][]byte{}
		for j := int64(0); j < cp.proofLen; j++ {
			proof = append(proof, cp.proof[j].h)
		}
		if err := realVerifier.VerifyConsistencyProof(cp.snapshot1, cp.snapshot2, roots[cp.snapshot1-1].h, roots[cp.snapshot2-1].h, proof); err != nil {
			return nil, nil, fmt.Errorf("consistency %d->%d: %v", cp.snapshot1, cp.snapshot2, err)
		}
		st.consistencyOK++
		st.consistencySize[cp.snapshot1] = true
		st.consistencySize[cp.snapshot2] = true
	}

	// ---- scanner FourEntrySTH (not a known answer; see deviations)
	four, err := scannerFourEntry()
	if err != nil {
		return nil, nil, err
	}
	st.four = four

	// ---- the RFC 9162 section 2.1.3.2 answer for every case
	discrepancies := []string{}
	for i := range incs {
		r, err := rfcVerifyCase(incs[i])
		if err != nil {
			return nil, nil, err
		}
		st.cases++
		if r != incs[i].Valid {
			rv := r
			incs[i].RFC9162Valid = &rv
			discrepancies = append(discrepancies, rfcDisagreement(incs[i]))
		} else {
			st.rfcAgree++
		}
	}

	f := &Fixture{
		Implementation: modulePath,
		Version:        moduleVersion,
		License:        "Apache-2.0",
		Sources:        sources,
		EmptyRoot:      &emptyRoot,
		HashChecks:     hcs,
		Trees:          trees,
		Inclusion:      incs,
		Deviations:     []string{fourEntryDeviation(four)},
		Discrepancies:  discrepancies,
		Notes:          notes(st),
	}
	return f, st, nil
}

// confirmCertLeaf rebuilds the test-cert leaf with the module's own code, from
// the vendored testdata/test-cert.pem + test-cert.proof and from the testdata
// package.
func confirmCertLeaf(modDir string, leafBytes, leafHash []byte) error {
	certB, err := os.ReadFile(filepath.Join(modDir, "testdata", "test-cert.pem"))
	if err != nil {
		return err
	}
	der, _ := pem.Decode(certB)
	sctB, err := os.ReadFile(filepath.Join(modDir, "testdata", "test-cert.proof"))
	if err != nil {
		return err
	}
	var sct ct.SignedCertificateTimestamp
	if _, err := tls.Unmarshal(sctB, &sct); err != nil {
		return err
	}
	leaf := ct.CreateX509MerkleTreeLeaf(ct.ASN1Cert{Data: der.Bytes}, sct.Timestamp)
	b, err := tls.Marshal(*leaf)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, leafBytes) {
		return errors.New("tls.Marshal(CreateX509MerkleTreeLeaf(test-cert.pem)) != serialization_test.go:383 literal")
	}
	h, err := ct.LeafHashForLeaf(leaf)
	if err != nil || !bytes.Equal(h[:], leafHash) {
		return fmt.Errorf("ct.LeafHashForLeaf(test-cert) mismatch: %v", err)
	}
	chain, err := x509util.CertificatesFromPEM([]byte(testdata.TestCertPEM + testdata.CACertPEM))
	if err != nil {
		return err
	}
	var sct2 ct.SignedCertificateTimestamp
	if _, err := tls.Unmarshal(testdata.TestCertProof, &sct2); err != nil {
		return err
	}
	h2, err := ctutil.LeafHash(chain, &sct2, false)
	if err != nil || !bytes.Equal(h2[:], leafHash) {
		return fmt.Errorf("ctutil.LeafHash(cert) mismatch: %v", err)
	}
	return nil
}

func precertLeaf() ([]byte, []byte, error) {
	want, err := base64.StdEncoding.DecodeString(testdata.TestPreCertB64LeafHash)
	if err != nil {
		return nil, nil, err
	}
	var sct ct.SignedCertificateTimestamp
	if _, err := tls.Unmarshal(testdata.TestPreCertProof, &sct); err != nil {
		return nil, nil, err
	}
	chain, err := x509util.CertificatesFromPEM([]byte(testdata.TestPreCertPEM + testdata.CACertPEM))
	if err != nil {
		return nil, nil, err
	}
	h, err := ctutil.LeafHash(chain, &sct, false)
	if err != nil || !bytes.Equal(h[:], want) {
		return nil, nil, fmt.Errorf("ctutil.LeafHash(precert) mismatch: %v", err)
	}
	leaf, err := ct.MerkleTreeLeafFromChain(chain, ct.PrecertLogEntryType, sct.Timestamp)
	if err != nil {
		return nil, nil, err
	}
	b, err := tls.Marshal(*leaf)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(hasher.HashLeaf(b), want) {
		return nil, nil, errors.New("HashLeaf(precert leaf) != TestPreCertB64LeafHash")
	}
	// The embedded-SCT case must reach the same leaf.
	echain, err := x509util.CertificatesFromPEM([]byte(testdata.TestEmbeddedCertPEM + testdata.CACertPEM))
	if err != nil {
		return nil, nil, err
	}
	he, err := ctutil.LeafHash(echain, &sct, true)
	if err != nil || !bytes.Equal(he[:], want) {
		return nil, nil, fmt.Errorf("ctutil.LeafHash(embedded) mismatch: %v", err)
	}
	eleaf, err := ct.MerkleTreeLeafForEmbeddedSCT(echain, sct.Timestamp)
	if err != nil {
		return nil, nil, err
	}
	eb, err := tls.Marshal(*eleaf)
	if err != nil || !bytes.Equal(eb, b) {
		return nil, nil, fmt.Errorf("embedded-SCT leaf bytes differ from precert leaf bytes: %v", err)
	}
	return b, want, nil
}

var sources = []string{
	"types.go:59-60 TreeLeafPrefix = 0x00, TreeNodePrefix = 0x01",
	"merkletree/tree_hasher.go:34-47 HashEmpty (SHA-256 of the empty string), HashLeaf (0x00 prefix), HashChildren (0x01 prefix)",
	"merkletree/merkle_verifier.go:45-117 VerifyInclusionProof, VerifyInclusionProofByHash, RootFromInclusionProof, RootFromInclusionProofAndHash (the verifier behind every verdict here)",
	"merkletree/merkle_verifier.go:217-223 parent, isRightChild (helpers of that verifier)",
	"merkletree/merkle_verifier.go:119-215 VerifyConsistencyProof (used only to cross-confirm roots)",
	"merkletree/merkle_tree_interface.go:18-53 MerkleTreeInterface, FullMerkleTreeInterface: declared, never implemented in the module (no Go tree builder or prover)",
	"merkletree/tree_hasher_test.go:24-69 test vector types, sha256EmptyHash, dh, getTestVector: empty hash, 3 leaf hashes, 1 node hash (getTestVector is defined but not called by any upstream test)",
	"merkletree/merkle_verifier_test.go:30-32 sha256EmptyTreeHash",
	"merkletree/merkle_verifier_test.go:34-119 verifierCheck: the known-good check plus the corruption set applied to every known-good inclusion proof",
	"merkletree/merkle_verifier_test.go:229-240 getInputs: the 8 leaf inputs",
	"merkletree/merkle_verifier_test.go:242-275 getInclusionTestVector: 5 inclusion proofs plus a skipped placeholder at index 0",
	"merkletree/merkle_verifier_test.go:277-287 getRoots: roots for tree sizes 1..8 over getInputs",
	"merkletree/merkle_verifier_test.go:289-319 getConsistencyProofs: 4 consistency proofs (outside this schema; used to cross-confirm roots)",
	"merkletree/merkle_verifier_test.go:321-350 TestVerifyInclusionProofTreeSizeOne: size-1 proof from a real CT instance, root at line 347",
	"merkletree/merkle_verifier_test.go:352-402 TestVerifyInclusionProof: 8 invalid path/root calls (lines 356-378) and the loop over getInclusionTestVector()[1..5] (lines 384-400)",
	"serialization_test.go:359-388 TestX509MerkleTreeLeafHash: serialized MerkleTreeLeaf for testdata/test-cert.pem (hex literal at line 383)",
	"testdata/certs.go:394-400 TestCertB64LeafHash, TestPreCertB64LeafHash",
	"testdata/test-cert.pem:1-60 certificate behind the size-1 tree; testdata/test-cert.proof (118-byte binary SCT, whole file) its timestamp",
	"ctutil/ctutil_test.go:27-90 TestLeafHash: leaf hashes for the cert, precert and embedded-SCT cases",
	"scanner/scanner_test_data.go:23-400 FourEntrySTH (tree_size 4 root, lines 23-27), FourEntries (28-264), Entry0..Entry3 (266-357), makeParent and CalcRootHash (360-400): a non-RFC test-data helper, deliberately not a known answer (see deviations)",
}

func notes(st *genStats) string {
	var sizes []string
	for _, n := range []int64{1, 2, 3, 4, 5, 6, 7, 8} {
		if st.consistencySize[n] {
			sizes = append(sizes, strconv.FormatInt(n, 10))
		}
	}
	return strings.Join([]string{
		"Version choice: certificate-transparency-go shipped its own RFC 6962 Merkle code only in package merkletree, present from v1.0.1 through v1.0.16 with identical test vectors in every release (VerifyInclusionProofByHash exists from v1.0.4; from v1.0.13 the prefixes come from ct.TreeLeafPrefix/TreeNodePrefix, same values). v1.0.17 removed it and imports github.com/google/trillian/merkle; v1.2.x and v1.3.x import github.com/transparency-dev/merkle. v1.0.16 is therefore the last version with its own implementation and fixtures, and is the one used.",
		"What the package contains: a TreeHasher (HashEmpty, HashLeaf with prefix 0x00, HashChildren with prefix 0x01, SHA-256 supplied by the caller) and a MerkleVerifier (inclusion and consistency). MerkleTreeInterface and FullMerkleTreeInterface are declared but never implemented anywhere in the module, so there is no Go tree builder and no proof generator. Tree roots are confirmed two ways: an RFC 9162 MTH recursion in the Go program that hashes only through the module's HashLeaf and HashChildren, and the module's own verifier (VerifyInclusionProofByHash) accepting proofs against each published root. Published inclusion proofs cover getInputs() tree sizes 1, 3, 5 and 8 plus the real-CT size-1 tree; the " + strconv.Itoa(st.consistencyOK) + " published consistency proofs (merkle_verifier_test.go:294-319, outside this schema) pass the module's VerifyConsistencyProof and so also confirm the roots for sizes " + strings.Join(sizes, ", ") + "; sizes 4 and 7 are confirmed by the verifier only through the generated cases.",
		"RFC conformance: identical hash primitives (SHA-256, 0x00 leaf prefix, 0x01 node prefix, empty tree = SHA-256 of the empty string). The inclusion verifier is the classic C++ CT algorithm (walk nodeIndex/lastNode up the tree, skip a level when the node is the last one and has no sibling); it is equivalent to RFC 9162 section 2.1.3.2: it rejects leaf_index >= tree_size, leaf_index < 0 and tree_size < 1, consumes the path bottom to top, and rejects a path that is one element too short or too long. Every published valid path equals the RFC 9162 PATH computed over the published leaves, and every published root equals the RFC 9162 MTH. No deviation found. Leniencies that are not a change to the tree: the verifier never checks that the leaf hash, the path elements or the root are 32 bytes (it only rejects a zero-length computed root); in the published cases a zero-length path element only ever appears as an extra element, which the path-length check rejects.",
		"Leaf data: the published inputs are 0, 1, 2, 4, 8 and 16 bytes long, the real-CT leaf is a " + strconv.Itoa(st.testCertLeafLen) + "-byte serialized MerkleTreeLeaf and the precert leaf in hash_checks is " + strconv.Itoa(st.precertLeafLen) + " bytes; none is 32 bytes. A library whose public API takes only 32-byte leaf data must start from leaf_hashes; hash_checks of kind leaf can only be checked as SHA-256(0x00 || input) directly.",
		"Negative cases: every published inclusion case is the materialized output of the upstream code itself. upstream_vectors.go holds merkle_verifier_test.go:30-119 (verifierCheck), 219-319 (vectors), 322-349 and 353-401 (the two inclusion test bodies), tree_hasher_test.go:24-69 and serialization_test.go:383 byte for byte (checked on every run against vendored copies of those upstream files, see below), and runs them against a recording wrapper around the module's MerkleVerifier; each case name gives the upstream line of the call. verifierCheck applies 12 corruptions to each of the 6 known-good proofs, plus a truncated proof when the path is non-empty and one replaced element per path element; TestVerifyInclusionProof adds 8 direct invalid path/root calls. All upstream expectations hold. An RFC 9162 section 2.1.3.2 verifier written from the RFC text over the module's hasher gives the module's answer on " + strconv.Itoa(st.rfcAgree) + " of " + strconv.Itoa(st.cases) + " cases, so " + rfcSentence(st) + " Some negative cases use inputs outside a strict API's domain: leaf_index -1, tree_size 0, an empty root (\"\") and zero-length path elements (\"\"); a consumer should count an argument error raised for them as valid=false.",
		"Not included: getInclusionTestVector()[0] ({0, 0, 0}) is a placeholder the upstream loop skips (\"i = 0 is an invalid path\") and has no root. The consistency proofs and verifierConsistencyCheck corruptions are outside this inclusion-only schema. tree_hasher_test.go's collision tests (Hello/World) assert only inequalities, with no hard-coded values. client/logclient_test.go ProofByHashResp, the STH root hashes in client, gossip, loglist, dnsclient and signatures tests, and the trillian/ctfe handler mocks carry no leaves or trees to rebuild, so they are not Merkle fixtures. tree_hasher_test.go getTestVector() is defined but never called by an upstream test; its values are included and reproduce.",
		"Generated cases: every (leaf_index, tree_size) for tree sizes 1..8 over getInputs(), with the path from an RFC 9162 PATH recursion in the Go program built on the module's hasher, each accepted by the module's verifier against the published getRoots() value. Names start with \"generated:\"; every other inclusion case is published.",
		"Not a known answer, deliberately: scanner/scanner_test_data.go:23-27 hard-codes a tree_size 4 root, FourEntrySTH sha256_root_hash " + st.four.sthRootB64 + " (hex " + hx(st.four.sthRoot) + "), over the four entries Entry0..Entry3. It is produced by the scanner package's test-data helper CalcRootHash, which is not RFC 6962/9162: no 0x00 leaf prefix, no 0x01 node prefix, and each parent hashes only the first 31 bytes of each child (makeParent's 31-byte copies). The RFC 9162 MTH of the same entries is " + hx(st.four.rfcRoot) + "; the module's own merkletree verifier accepts every entry against that root and rejects every entry against the FourEntrySTH value. The Go program reproduces the FourEntrySTH value with scanner.CalcRootHash and with that non-RFC procedure on every run; it is listed under deviations (a non-conformant helper elsewhere in the module, not the merkletree code) so that nobody adds it later as a known answer.",
		"Running it: the Go program lives at interop/go/certificate-transparency-go/ in the truestamp_merkle library, and this fixture at vectors/interop/certificate-transparency-go.json. From the program directory, go run . -fixtures ../../../vectors/interop/certificate-transparency-go.json checks the fixture and prints one OK line, or one FAIL line per problem and exit status 1; go run . -fixtures ../../../vectors/interop/certificate-transparency-go.json -write regenerates it first; adding -ours ../../../vectors/merkle.json also checks the library's own vectors with the module's hasher and verifier and prints a second OK line. -fixtures is required. Apart from those paths the program reads only files inside its own directory: the upstream files it runs or compares at run time (merkletree/merkle_verifier_test.go, merkletree/tree_hasher_test.go, serialization_test.go, testdata/test-cert.pem, testdata/test-cert.proof, and the Apache-2.0 LICENSE) are vendored byte for byte from the v1.0.16 module zip under " + vendoredRel + "/ there, and the program pins each file's SHA-256. It needs Go 1.26 and the modules pinned by go.sum, fetched once into the module cache, and no network after that. This fixture is self-contained, so ExUnit reads it with no Go dependency; the Go program is the provenance check to rerun whenever the fixture is regenerated, and the library's opt-in go_interop tests run it with -ours and require exit status 0.",
	}, " ")
}

// ---------------------------------------------------------------------------
// Encoding and independent checks
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

func unhex(s string) ([]byte, error) { return hex.DecodeString(s) }

func unhexList(ss []string) ([][]byte, error) {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		b, err := unhex(s)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

type checkStats struct {
	published, generated, valid, invalid int
}

// checkFixture checks every value of the decoded fixture against the module.
func checkFixture(f *Fixture) (*checkStats, []string) {
	var errs []string
	bad := func(format string, a ...interface{}) { errs = append(errs, fmt.Sprintf(format, a...)) }
	st := &checkStats{}

	if f.Implementation != modulePath || f.Version != moduleVersion {
		bad("implementation/version %s@%s", f.Implementation, f.Version)
	}
	if f.EmptyRoot == nil || *f.EmptyRoot != hx(hasher.HashEmpty()) {
		bad("empty_root not reproduced by HashEmpty()")
	}
	for _, h := range f.HashChecks {
		switch h.Kind {
		case "leaf":
			in, err := unhex(derefOr(h.InputHex))
			if err != nil || h.InputHex == nil || hx(hasher.HashLeaf(in)) != h.Hash {
				bad("hash_check %q: HashLeaf mismatch", h.Name)
			}
		case "node":
			l, e1 := unhex(derefOr(h.Left))
			r, e2 := unhex(derefOr(h.Right))
			if e1 != nil || e2 != nil || h.Left == nil || h.Right == nil || hx(hasher.HashChildren(l, r)) != h.Hash {
				bad("hash_check %q: HashChildren mismatch", h.Name)
			}
		default:
			bad("hash_check %q: kind %q", h.Name, h.Kind)
		}
	}

	type treeKey struct {
		size int64
		root string
	}
	treeLeaves := map[treeKey][]string{}
	for _, t := range f.Trees {
		if t.LeafDataRule != nil {
			bad("tree %q: leaf_data_rule is set, but every tree here lists its leaves", t.Name)
		}
		if int64(len(t.LeafHashes)) != t.TreeSize {
			bad("tree %q: %d leaf hashes for size %d", t.Name, len(t.LeafHashes), t.TreeSize)
			continue
		}
		if t.LeafData != nil {
			if len(t.LeafData) != len(t.LeafHashes) {
				bad("tree %q: leaf_data/leaf_hashes length", t.Name)
			}
			for i := range t.LeafData {
				d, err := unhex(t.LeafData[i])
				if err != nil || i >= len(t.LeafHashes) || hx(hasher.HashLeaf(d)) != t.LeafHashes[i] {
					bad("tree %q: leaf %d hash not reproduced by HashLeaf", t.Name, i)
				}
			}
		}
		lh, err := unhexList(t.LeafHashes)
		root, err2 := unhex(t.Root)
		if err != nil || err2 != nil {
			bad("tree %q: bad hex", t.Name)
			continue
		}
		if !bytes.Equal(rfcMTH(lh), root) {
			bad("tree %q: root not reproduced by RFC 9162 MTH over the module's hasher", t.Name)
		}
		// The module's verifier must accept every leaf against this root.
		for m := range lh {
			if err := realVerifier.VerifyInclusionProofByHash(int64(m), t.TreeSize, rfcPath(lh, m), root, lh[m]); err != nil {
				bad("tree %q: module verifier rejects leaf %d against the root: %v", t.Name, m, err)
			}
		}
		treeLeaves[treeKey{t.TreeSize, t.Root}] = t.LeafHashes
	}

	for _, c := range f.Inclusion {
		if strings.HasPrefix(c.Name, "generated:") {
			st.generated++
			if c.UpstreamExpectation != "none" {
				bad("inclusion %q: generated case with upstream expectation %q", c.Name, c.UpstreamExpectation)
			}
		} else {
			st.published++
		}
		leaf, e1 := unhex(c.LeafHash)
		path, e2 := unhexList(c.Path)
		root, e3 := unhex(c.Root)
		if e1 != nil || e2 != nil || e3 != nil {
			bad("inclusion %q: bad hex", c.Name)
			continue
		}
		accepted := realVerifier.VerifyInclusionProofByHash(c.LeafIndex, c.TreeSize, path, root, leaf) == nil
		if accepted != c.Valid {
			bad("inclusion %q: module verifier says %v, fixture says %v", c.Name, accepted, c.Valid)
		}
		// The RFC 9162 section 2.1.3.2 answer: where it differs from the
		// module's, the case must carry it in rfc9162_valid and discrepancies
		// must record it.
		switch rfc := rfcVerify(c.LeafIndex, c.TreeSize, leaf, path, root); {
		case rfc != accepted && (c.RFC9162Valid == nil || *c.RFC9162Valid != rfc || !mentions(f.Discrepancies, c.Name)):
			bad("inclusion %q: module verifier says %v, RFC 9162 2.1.3.2 says %v, and rfc9162_valid/discrepancies do not record it", c.Name, accepted, rfc)
		case rfc == accepted && c.RFC9162Valid != nil:
			bad("inclusion %q: rfc9162_valid is set, but the module agrees with RFC 9162", c.Name)
		}
		if accepted {
			st.valid++
			got, err := realVerifier.RootFromInclusionProofAndHash(c.LeafIndex, c.TreeSize, path, leaf)
			if err != nil || !bytes.Equal(got, root) {
				bad("inclusion %q: RootFromInclusionProofAndHash does not give the root", c.Name)
			}
			lhs, ok := treeLeaves[treeKey{c.TreeSize, c.Root}]
			if !ok || c.LeafIndex < 0 || c.LeafIndex >= int64(len(lhs)) || lhs[c.LeafIndex] != c.LeafHash {
				bad("inclusion %q: no fixture tree holds this leaf at this index under this root", c.Name)
			} else if lb, err := unhexList(lhs); err != nil || !equalProofs(rfcPath(lb, int(c.LeafIndex)), path) {
				bad("inclusion %q: path differs from RFC 9162 PATH", c.Name)
			}
		} else {
			st.invalid++
		}
		switch c.UpstreamExpectation {
		case "valid", "invalid":
			if (c.UpstreamExpectation == "valid") != c.Valid && !mentions(f.Discrepancies, c.Name) {
				bad("inclusion %q: upstream expects %s, module says valid=%v, and discrepancies does not record it", c.Name, c.UpstreamExpectation, c.Valid)
			}
		case "none":
		default:
			bad("inclusion %q: upstream_expectation %q", c.Name, c.UpstreamExpectation)
		}
	}
	// The one deviations entry (scanner FourEntrySTH) is re-derived with the
	// module's own scanner and merkletree code.
	if four, err := scannerFourEntry(); err != nil {
		bad("scanner FourEntrySTH: %v", err)
	} else if len(f.Deviations) != 1 || f.Deviations[0] != fourEntryDeviation(four) {
		bad("deviations must hold exactly the scanner FourEntrySTH entry the module reproduces")
	}
	return st, errs
}

func derefOr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func mentions(list []string, name string) bool {
	for _, s := range list {
		if strings.Contains(s, name) {
			return true
		}
	}
	return false
}

func equalProofs(a, b [][]byte) bool {
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

func firstDiff(a, b []byte) string {
	al := strings.Split(string(a), "\n")
	bl := strings.Split(string(b), "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("line %d: file has %.200q, regeneration has %.200q", i+1, x, y)
		}
	}
	return "no line differs"
}

// checkMain regenerates the fixture (rewriting the file first when write is
// set) and checks the file at abs. It returns the counts for the OK line, or
// the problems.
func checkMain(abs string, write bool) (string, []string) {
	if err := linkedVersionOK(); err != nil {
		return "", []string{err.Error()}
	}
	upDir, err := vendoredDir()
	if err != nil {
		return "", []string{err.Error()}
	}
	gen, gst, err := generate(upDir)
	if err != nil {
		return "", []string{"generation: " + err.Error()}
	}
	want, err := encode(gen)
	if err != nil {
		return "", []string{"encode: " + err.Error()}
	}
	if write {
		if err := os.WriteFile(abs, want, 0o644); err != nil {
			return "", []string{"write: " + err.Error()}
		}
	}

	got, err := os.ReadFile(abs)
	if err != nil {
		return "", []string{fmt.Sprintf("read %s: %v", abs, err)}
	}
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(got))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return "", []string{fmt.Sprintf("parse %s: %v", abs, err)}
	}
	cst, errs := checkFixture(&f)
	if !bytes.Equal(got, want) {
		errs = append(errs, "fixture file is not what the upstream vectors and the module regenerate: "+firstDiff(got, want))
	}
	if bytes.ContainsRune(got, '\u2014') {
		errs = append(errs, "fixture file contains an em dash")
	}
	if len(errs) > 0 {
		return "", errs
	}
	return fmt.Sprintf("empty_root 1, hash_checks %d, trees %d, inclusion %d (published %d, generated %d; valid %d, invalid %d), RFC 9162 agreement %d/%d, discrepancies %d, deviations %d, verbatim upstream blocks %d, vendored upstream files %d, consistency proofs %d/%d",
		len(f.HashChecks), len(f.Trees), len(f.Inclusion), cst.published, cst.generated,
		cst.valid, cst.invalid, gst.rfcAgree, gst.cases, len(f.Discrepancies), len(f.Deviations), gst.blocks, len(vendoredSHA256), gst.consistencyOK, gst.consistencyAll), nil
}

// guarded runs a check and turns a panic into a problem, so that no input can
// end the program with a Go panic (exit status 2) instead of FAIL lines.
func guarded(check func() (string, []string)) (counts string, problems []string) {
	defer func() {
		if r := recover(); r != nil {
			counts, problems = "", []string{fmt.Sprintf("internal error: %v", r)}
		}
	}()
	return check()
}

const programName = "certificate-transparency-go"

const usageText = `usage: go run . -fixtures <path> [-write] [-ours <path>]

  -fixtures <path>  the fixture to check (required); in the library it is
                    ../../../vectors/interop/certificate-transparency-go.json
  -write            regenerate the fixture from the upstream vectors and the
                    module, then check it
  -ours <path>      also check the truestamp_merkle library's own vectors,
                    ../../../vectors/merkle.json, with the module
`

// oneLine folds a message onto a single output line.
func oneLine(s string) string {
	return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
}

// parseArgs reads the command line. It returns the fixture path, the -ours
// path ("" when not given) and -write, or help=true for -h, or the reason the
// command line is not usable.
func parseArgs(args []string) (fixtures, ours string, write, help bool, usageErr string) {
	fs := flag.NewFlagSet(programName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fixturesFlag := fs.String("fixtures", "", "")
	oursFlag := fs.String("ours", "", "")
	writeFlag := fs.Bool("write", false, "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", "", false, true, ""
		}
		return "", "", false, false, err.Error()
	}
	if fs.NArg() != 0 {
		return "", "", false, false, fmt.Sprintf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	switch {
	case !set["fixtures"]:
		return "", "", false, false, "-fixtures <path> is required"
	case *fixturesFlag == "":
		return "", "", false, false, "-fixtures needs a non-empty path"
	case set["ours"] && *oursFlag == "":
		return "", "", false, false, "-ours needs a non-empty path"
	}
	return *fixturesFlag, *oursFlag, *writeFlag, false, ""
}

// The program parses its own flag set, not flag.CommandLine: the imported
// github.com/google/certificate-transparency-go root package registers
// -allow_verification_with_non_compliant_keys on flag.CommandLine at init
// (signatures.go:33), and that flag is neither accepted nor listed here.
func main() {
	os.Exit(run(os.Args[1:]))
}

// run returns the exit status. Every phase is guarded, so a panic anywhere
// becomes one FAIL line and exit status 1.
func run(args []string) (status int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("FAIL usage: internal error: " + oneLine(fmt.Sprint(r)))
			status = 1
		}
	}()
	id := modulePath + "@" + moduleVersion

	fixtures, ours, write, help, usageErr := parseArgs(args)
	if help {
		fmt.Fprint(os.Stderr, usageText)
		return 0
	}
	if usageErr != "" {
		fmt.Println("FAIL usage: " + oneLine(usageErr))
		return 1
	}
	// Both paths are made absolute before the fixture check changes directory.
	abs, err := filepath.Abs(fixtures)
	if err != nil {
		fmt.Println("FAIL usage: -fixtures: " + oneLine(err.Error()))
		return 1
	}
	oursAbs := ""
	if ours != "" {
		if oursAbs, err = filepath.Abs(ours); err != nil {
			fmt.Println("FAIL usage: -ours: " + oneLine(err.Error()))
			return 1
		}
	}

	failed := false
	report := func(phase, counts string, problems []string) {
		if len(problems) == 0 {
			fmt.Printf("OK %s %s: %s\n", phase, id, oneLine(counts))
			return
		}
		failed = true
		const maxLines = 50
		for i, p := range problems {
			if i == maxLines {
				fmt.Printf("FAIL %s %s: %d more problems not shown\n", phase, id, len(problems)-maxLines)
				break
			}
			fmt.Printf("FAIL %s %s: %s\n", phase, id, oneLine(p))
		}
	}
	counts, problems := guarded(func() (string, []string) { return checkMain(abs, write) })
	report("fixtures", counts, problems)
	if oursAbs != "" {
		counts, problems := guarded(func() (string, []string) { return checkOurs(oursAbs) })
		report("ours", counts, problems)
	}
	if failed {
		return 1
	}
	return 0
}
