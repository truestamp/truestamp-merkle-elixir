// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains material from github.com/codenotary/merkletree@v0.1.2: the two
// declaration lines of data_test.go (lines 23 and 91) that locateData
// compares, and the names of the upstream test functions it runs, Copyright
// 2019-2020 vChain, Inc., licensed under the Apache License, Version 2.0
// (LICENSE-codenotary-merkletree; see NOTICE).

package main

// Provenance plumbing: the vendored upstream files, the byte-for-byte check
// of every verbatim block compiled into this program, the mapping from a
// running line of upstream_tests.go back to its upstream file and line, a
// parser that locates every testRoots / testPaths literal in data_test.go by
// line, and the runner for the copied upstream tests.

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/truestamp/truestamp-merkle-elixir/interop/go/codenotary-merkletree/internal/assert"
	"github.com/truestamp/truestamp-merkle-elixir/interop/go/codenotary-merkletree/internal/testing"
)

//go:embed testdata/data_test.go.txt testdata/tree_test.go.txt testdata/mth_test.go.txt testdata/example_test.go.txt LICENSE-codenotary-merkletree
var upstreamFS embed.FS

//go:embed upstream_data.go upstream_tests.go
var ownFS embed.FS

// SHA-256 of each vendored file, equal to the file in the module cache for
// github.com/codenotary/merkletree@v0.1.2 (whose zip go.sum pins) when this
// program was written. NOTICE has the re-check against the module cache.
var vendoredSHA256 = map[string]string{
	"testdata/data_test.go.txt":     "031572bc7e37c7cfaffa4b0cac1ae179adb23d01766c2ac4419ca82bf0106280",
	"testdata/tree_test.go.txt":     "c29eddef8528c0abf690607170453f29ea3c0b34941e0154b0ca5deb92cc953d",
	"testdata/mth_test.go.txt":      "171e66b9d5e82adaed459eb8025da6e66b74e4116e6273a408712836668e8019",
	"testdata/example_test.go.txt":  "edaf36f97532307dc175823ddadb2920d72fe440a71700d54bf00f06936c3e38",
	"LICENSE-codenotary-merkletree": "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
}

// upstreamLines returns the lines of a vendored upstream file ("data_test.go"
// and so on); element 0 is line 1.
func upstreamLines(name string) ([]string, error) {
	raw, err := upstreamFS.ReadFile("testdata/" + name + ".txt")
	if err != nil {
		return nil, err
	}
	return strings.Split(string(raw), "\n"), nil
}

func checkVendored() error {
	for name, want := range vendoredSHA256 {
		raw, err := upstreamFS.ReadFile(name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != want {
			return fmt.Errorf("%s: SHA-256 %s, pinned %s", name, got, want)
		}
	}
	return nil
}

type block struct {
	ownFile     string // upstream_data.go or upstream_tests.go
	file        string // upstream file name
	first, last int    // upstream line range, 1-based, inclusive
	ownFirst    int    // line in ownFile holding upstream line `first`
	lines       []string
}

var (
	blocks  []block
	beginRe = regexp.MustCompile(`^// BEGIN (\S+):(\d+)-(\d+)$`)
)

// loadBlocks reads the BEGIN/END blocks of both verbatim files and checks
// each against the vendored upstream file, byte for byte.
func loadBlocks() error {
	blocks = nil
	for _, own := range []string{"upstream_data.go", "upstream_tests.go"} {
		raw, err := ownFS.ReadFile(own)
		if err != nil {
			return err
		}
		lines := strings.Split(string(raw), "\n")
		for i := 0; i < len(lines); i++ {
			m := beginRe.FindStringSubmatch(lines[i])
			if m == nil {
				continue
			}
			first, _ := strconv.Atoi(m[2])
			last, _ := strconv.Atoi(m[3])
			j := i + 1
			for j < len(lines) && lines[j] != "// END" {
				j++
			}
			if j == len(lines) {
				return fmt.Errorf("%s: BEGIN at line %d has no END", own, i+1)
			}
			b := block{ownFile: own, file: m[1], first: first, last: last, ownFirst: i + 2, lines: lines[i+1 : j]}
			if len(b.lines) != last-first+1 {
				return fmt.Errorf("%s: block %s:%d-%d holds %d lines", own, b.file, first, last, len(b.lines))
			}
			up, err := upstreamLines(b.file)
			if err != nil {
				return err
			}
			if last > len(up) {
				return fmt.Errorf("%s has %d lines, block wants %d-%d", b.file, len(up), first, last)
			}
			for k, got := range b.lines {
				if want := up[first-1+k]; got != want {
					return fmt.Errorf("%s line %d differs from upstream %s:%d: upstream %q, here %q",
						own, b.ownFirst+k, b.file, first+k, want, got)
				}
			}
			blocks = append(blocks, b)
			i = j
		}
	}
	if len(blocks) != 9 {
		return fmt.Errorf("expected 9 verbatim blocks, found %d", len(blocks))
	}
	return nil
}

// callerUpstream maps the caller of the function calling it (skip=1) to its
// upstream file and line, when that caller is inside a verbatim block.
func callerUpstream(skip int) (string, int) {
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return "", 0
	}
	own := filepath.Base(file)
	for _, b := range blocks {
		if b.ownFile == own && line >= b.ownFirst && line < b.ownFirst+len(b.lines) {
			return b.file, b.first + (line - b.ownFirst)
		}
	}
	return "", 0
}

// ---------------------------------------------------------------------------
// data_test.go literal locator
// ---------------------------------------------------------------------------

type litNode struct {
	line, endLine int
	kids          []*litNode
	bytes         []byte
}

// parseComposite parses the composite literal that starts at the first '{'
// on line startLine (1-based) of src and returns its tree of braces with the
// line of every opening brace. Numbers may be decimal or 0x hex bytes.
func parseComposite(src []string, startLine int) (*litNode, error) {
	var stack []*litNode
	var root *litNode
	started := false
	for ln := startLine; ln <= len(src); ln++ {
		s := src[ln-1]
		c := 0
		if !started {
			c = strings.IndexByte(s, '{')
			if c < 0 {
				return nil, fmt.Errorf("line %d: no '{'", ln)
			}
			started = true
		}
		for c < len(s) {
			ch := s[c]
			switch {
			case ch == '{':
				stack = append(stack, &litNode{line: ln})
				c++
			case ch == '}':
				if len(stack) == 0 {
					return nil, fmt.Errorf("line %d: unbalanced '}'", ln)
				}
				n := stack[len(stack)-1]
				n.endLine = ln
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					root = n
					return root, nil
				}
				p := stack[len(stack)-1]
				p.kids = append(p.kids, n)
				c++
			case ch == ',' || ch == ' ' || ch == '\t':
				c++
			case ch >= '0' && ch <= '9':
				e := c
				for e < len(s) && (s[e] >= '0' && s[e] <= '9' || s[e] >= 'a' && s[e] <= 'f' || s[e] == 'x') {
					e++
				}
				v, err := strconv.ParseUint(s[c:e], 0, 8)
				if err != nil {
					return nil, fmt.Errorf("line %d: %v", ln, err)
				}
				if len(stack) == 0 {
					return nil, fmt.Errorf("line %d: number outside braces", ln)
				}
				top := stack[len(stack)-1]
				top.bytes = append(top.bytes, byte(v))
				c = e
			default:
				return nil, fmt.Errorf("line %d col %d: unexpected %q", ln, c+1, ch)
			}
		}
	}
	return nil, errors.New("literal never closed")
}

// dataLines locates the upstream line of every literal the fixture cites.
type dataLines struct {
	rootLine [65]int     // testRoots[j]
	pathSpan [9][][2]int // testPaths[idx][i]: first and last line of the literal
	elemLine [9][][]int  // testPaths[idx][i][k]
	byValue  map[[32]byte]string
}

func locateData() (*dataLines, error) {
	src, err := upstreamLines("data_test.go")
	if err != nil {
		return nil, err
	}
	if src[22] != "var testRoots = [][sha256.Size]byte{" || src[90] != "var testPaths = [][][][32]uint8{" {
		return nil, errors.New("data_test.go: testRoots / testPaths not at lines 23 / 91")
	}
	roots, err := parseComposite(src, 23)
	if err != nil {
		return nil, fmt.Errorf("testRoots: %v", err)
	}
	paths, err := parseComposite(src, 91)
	if err != nil {
		return nil, fmt.Errorf("testPaths: %v", err)
	}
	if roots.endLine != 89 || paths.endLine != 213 {
		return nil, fmt.Errorf("literal spans end at %d and %d, want 89 and 213", roots.endLine, paths.endLine)
	}
	d := &dataLines{byValue: map[[32]byte]string{}}
	if len(roots.kids) != len(testRoots) || len(roots.kids) != 65 {
		return nil, fmt.Errorf("testRoots: parsed %d, compiled %d", len(roots.kids), len(testRoots))
	}
	for j, k := range roots.kids {
		if !bytes.Equal(k.bytes, testRoots[j][:]) || k.line != k.endLine {
			return nil, fmt.Errorf("testRoots[%d]: parsed literal differs from compiled value", j)
		}
		d.rootLine[j] = k.line
		d.note(testRoots[j], fmt.Sprintf("data_test.go:%d testRoots[%d]", k.line, j))
	}
	if len(paths.kids) != len(testPaths) || len(paths.kids) != 9 {
		return nil, fmt.Errorf("testPaths: parsed %d sizes, compiled %d", len(paths.kids), len(testPaths))
	}
	for idx, size := range paths.kids {
		if len(size.kids) != len(testPaths[idx]) || len(size.kids) != idx+1 {
			return nil, fmt.Errorf("testPaths[%d]: parsed %d paths, compiled %d", idx, len(size.kids), len(testPaths[idx]))
		}
		for i, p := range size.kids {
			if len(p.kids) != len(testPaths[idx][i]) {
				return nil, fmt.Errorf("testPaths[%d][%d]: parsed %d elements, compiled %d", idx, i, len(p.kids), len(testPaths[idx][i]))
			}
			d.pathSpan[idx] = append(d.pathSpan[idx], [2]int{p.line, p.endLine})
			var lines []int
			for k, e := range p.kids {
				if !bytes.Equal(e.bytes, testPaths[idx][i][k][:]) || e.line != e.endLine {
					return nil, fmt.Errorf("testPaths[%d][%d][%d]: parsed literal differs from compiled value", idx, i, k)
				}
				lines = append(lines, e.line)
				d.note(testPaths[idx][i][k], fmt.Sprintf("data_test.go:%d testPaths[%d][%d][%d]", e.line, idx, i, k))
			}
			d.elemLine[idx] = append(d.elemLine[idx], lines)
		}
	}
	return d, nil
}

// note keeps the first literal occurrence of each value.
func (d *dataLines) note(v [32]byte, where string) {
	if _, ok := d.byValue[v]; !ok {
		d.byValue[v] = where
	}
}

func lineRange(a, b int) string {
	if a == b {
		return strconv.Itoa(a)
	}
	return fmt.Sprintf("%d-%d", a, b)
}

// ---------------------------------------------------------------------------
// Running the copied upstream tests
// ---------------------------------------------------------------------------

// runUpstreamTests runs every copied upstream test against the real module.
// Every assertion must hold (they all do at v0.1.2), and every boolean
// assertion must follow the VerifyInclusion call whose result it checks.
func runUpstreamTests() error {
	recorded, lastCall = nil, nil
	var hookErr error
	assert.OnBool = func(value, expected bool) {
		if lastCall == nil || lastCall.asserted != nil || lastCall.result != value {
			if hookErr == nil {
				hookErr = fmt.Errorf("%s: a boolean assertion does not follow a VerifyInclusion call", currentUpstreamTest)
			}
			return
		}
		e := expected
		lastCall.asserted = &e
		lastCall.assertOK = value == expected
	}
	defer func() { assert.OnBool = nil }()

	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{"mth_test.go TestMTH", TestMTH},
		{"mth_test.go TestMPath", TestMPath},
		{"tree_test.go TestAppend", TestAppend},
		{"tree_test.go TestRoot", TestRoot},
		{"tree_test.go TestInclusionProof", TestInclusionProof},
		{"tree_test.go TestVerifyInclusion", TestVerifyInclusion},
		{"example_test.go TestInclusionPath", TestInclusionPath},
	}
	for _, tc := range tests {
		currentUpstreamTest = tc.name
		t := &testing.T{Name: tc.name}
		tc.fn(t)
		if len(t.Failures) > 0 {
			return fmt.Errorf("upstream %s fails against the module: %s", tc.name, t.Failures[0])
		}
	}
	currentUpstreamTest = ""
	if hookErr != nil {
		return hookErr
	}
	// TestVerifyInclusion: 4 edge calls, then for index 0..64, at 0..index,
	// i 0..at: sum over index of (index+1)(index+2)/2 = 47905 calls.
	// TestInclusionPath: 3 calls.
	want := 4 + 47905 + 3
	if len(recorded) != want {
		return fmt.Errorf("recorded %d VerifyInclusion calls, want %d", len(recorded), want)
	}
	for _, c := range recorded {
		if c.file == "" || c.asserted == nil || !c.assertOK {
			return fmt.Errorf("recorded call at %s:%d is unasserted or failed", c.file, c.line)
		}
	}
	return nil
}
