// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command transparency-dev-merkle checks truestamp_merkle's interop fixture
// for github.com/transparency-dev/merkle (the version pinned in go.mod) with
// that implementation's own functions and, with -write, first regenerates the
// fixture from the verbatim upstream literals and the implementation. With
// -ours it also checks truestamp_merkle's own known answers
// (vectors/merkle.json) with the implementation's functions.
//
// In the truestamp_merkle repository the program is interop/go/transparency-dev-merkle/
// and its fixture is vectors/interop/transparency-dev-merkle.json. From the
// program directory:
//
//	go run . -fixtures ../../../vectors/interop/transparency-dev-merkle.json
//	go run . -fixtures ../../../vectors/interop/transparency-dev-merkle.json -write
//	go run . -fixtures ../../../vectors/interop/transparency-dev-merkle.json -ours ../../../vectors/merkle.json
//
// -fixtures is required; -ours, when given, needs a non-empty path. On success
// the program prints one line per phase, "OK fixtures <module>@<version>:
// <counts>" and, with -ours, "OK ours <module>@<version>: <counts>", and exits
// 0. Each problem prints one line starting "FAIL fixtures " or "FAIL ours ",
// and the exit status is 1. A usage error (unknown flag, missing or empty
// value, positional argument) prints the single line "FAIL usage: <reason>"
// and exits 1; -h and -help print the usage to stderr and exit 0. Apart from
// the two named files it reads nothing at run time: the upstream main-branch
// testdata it cross-checks is embedded (testdata/upstream-main-inclusion).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

const (
	implModule  = "github.com/transparency-dev/merkle"
	implVersion = "v0.0.2"
	implLicense = "Apache-2.0"
)

// implID is the <module>@<version> of every result line.
const implID = implModule + "@" + implVersion

const usageLine = "usage: go run . -fixtures <path> [-write] [-ours <path>]"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) (status int) {
	phase := "usage"
	defer func() {
		if r := recover(); r != nil {
			if phase == "usage" {
				fmt.Println(oneLine(fmt.Sprintf("FAIL usage: panic: %v", r)))
			} else {
				fmt.Println(oneLine(fmt.Sprintf("FAIL %s %s: panic: %v", phase, implID, r)))
			}
			status = 1
		}
	}()

	fs := flag.NewFlagSet("transparency-dev-merkle", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fixturesPath := fs.String("fixtures", "", "path of the fixture file (required)")
	write := fs.Bool("write", false, "regenerate the fixture file from the upstream literals and the implementation, then check it")
	oursPath := fs.String("ours", "", "path of truestamp_merkle's vectors/merkle.json, checked with the implementation's functions")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stderr)
			fmt.Fprintln(os.Stderr, usageLine)
			fs.PrintDefaults()
			return 0
		}
		fmt.Println(oneLine("FAIL usage: " + err.Error()))
		return 1
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	switch {
	case fs.NArg() > 0:
		fmt.Println(oneLine(fmt.Sprintf("FAIL usage: unexpected argument %q", fs.Arg(0))))
		return 1
	case !set["fixtures"]:
		fmt.Println("FAIL usage: -fixtures <path> is required")
		return 1
	case *fixturesPath == "":
		fmt.Println("FAIL usage: -fixtures needs a non-empty path")
		return 1
	case set["ours"] && *oursPath == "":
		fmt.Println("FAIL usage: -ours needs a non-empty path")
		return 1
	}

	phase = "fixtures"
	if !checkFixtureFile(*fixturesPath, *write) {
		status = 1
	}
	if set["ours"] {
		phase = "ours"
		summary, errs := checkOurs(*oursPath)
		if len(errs) > 0 {
			for _, e := range errs {
				fmt.Printf("FAIL ours %s: %s\n", implID, e)
			}
			status = 1
		} else {
			fmt.Printf("OK ours %s: %s\n", implID, summary)
		}
	}
	return status
}

// guard runs one phase, turning a panic (a defect, or input no check
// anticipated) into a FAIL line instead of a crash.
func (c *checker) guard(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			c.fail("%s: panic: %v", what, r)
		}
	}()
	fn()
}

// checkFixtureFile checks (after regenerating, with write) the fixture file
// and prints its result line or lines; it reports whether everything passed.
func checkFixtureFile(fixturesPath string, write bool) bool {
	c := &checker{}
	report := func(counts string) bool {
		if len(c.errs) > 0 {
			for _, e := range c.errs {
				fmt.Printf("FAIL fixtures %s: %s\n", implID, e)
			}
			return false
		}
		fmt.Printf("OK fixtures %s: %s\n", implID, counts)
		return true
	}
	c.guard("build info", c.checkBuildInfo)
	c.guard("upstream self-check", c.selfCheckUpstream)
	c.guard("main vectors_test.go digests", c.checkSubtreeVectors)

	if write {
		c.guard("write", func() {
			if err := os.WriteFile(fixturesPath, canonical(build()), 0o644); err != nil {
				c.fail("write %s: %v", fixturesPath, err)
			}
		})
	}

	raw, err := os.ReadFile(fixturesPath)
	if err != nil {
		c.fail("read %s: %v", fixturesPath, err)
		return report("not checked")
	}
	var f Fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		c.fail("parse %s: %v", fixturesPath, err)
		return report("not checked")
	}
	if f.Implementation != implModule || f.Version != implVersion || f.License != implLicense {
		c.fail("header: implementation %q version %q license %q, want %q %q %q", f.Implementation, f.Version, f.License, implModule, implVersion, implLicense)
	}

	c.guard("fixture values", func() { c.checkFixture(&f) })
	c.guard("proof_test.go TestInclusion cases", func() { c.checkProofTestInclusion(&f) })
	c.guard("main vectors_test.go rows", func() { c.checkSubtreeVectorRows(&f) })
	c.guard("regeneration", func() { c.checkRegeneration(raw, &f) })
	c.guard("main testdata", func() { c.checkMainTestdata(&f) })

	counts := fmt.Sprintf("%d hash checks, %d trees (%d published, %d generated; %d by leaf_data_rule; %d leaves), %d inclusion cases (%d valid, %d invalid; %d published, %d generated), %d discrepancies, %d rfc9162_valid overrides; proof.VerifyInclusion verdict matched by trillian@v1.4.2 logverifier %d/%d and by an RFC 9162 section 2.1.3.2 transcription %d/%d; prover reproduced %d valid paths; proof_test.go TestInclusion %d rows, %d cases; main testdata %d/%d; main vectors_test.go digests %d/4 reproduced (TestSubtreeHashVectors over %d rows, TestSubtreeInclusionProofVectors over %d rows, %d with start = 0), %d start = 0 rows in the file; %d upstream literal checks; %d bytes",
		c.hashChecks, c.trees, c.publishedTrees, c.generatedTrees, c.ruleTrees, c.treeLeaves,
		c.inclusion, c.valid, c.invalid, c.publishedCases, c.generatedCases, c.discrepancies, c.overrides(&f),
		c.trillianAgreed, c.inclusion, c.rfcAgreed, c.inclusion, c.proverConfirmed,
		c.tiRows, c.tiCases, c.mainMatched, c.mainFiles,
		c.svDigests, c.svHashRows, c.svProofRows, c.svStart0Rows, c.svCases,
		c.literalChecks, len(raw))

	if len(raw) > maxFixtureBytes {
		c.fail("size: %d bytes, budget %d", len(raw), maxFixtureBytes)
	}
	return report(counts)
}

// maxFixtureBytes is the size budget of one fixture file (1.5 MB).
const maxFixtureBytes = 1_500_000

func (c *checker) overrides(f *Fixture) int {
	n := 0
	for _, in := range f.Inclusion {
		if in.RFC9162Valid != nil {
			n++
		}
	}
	return n
}

// checkBuildInfo confirms the implementation linked into this binary is the
// version the fixture names.
func (c *checker) checkBuildInfo() {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		c.fail("build info unavailable: cannot confirm the linked %s version", implModule)
		return
	}
	for _, d := range bi.Deps {
		if d.Path == implModule {
			if d.Replace != nil || d.Version != implVersion {
				c.fail("linked %s is %s (replace %v), want %s", implModule, d.Version, d.Replace, implVersion)
			}
			return
		}
	}
	c.fail("%s is not linked into this binary", implModule)
}
