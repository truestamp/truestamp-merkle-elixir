// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains material from github.com/codenotary/merkletree@v0.1.2: the prose
// below quotes short code fragments of mth.go and tree.go and cites its
// files by line, Copyright 2019-2020 vChain, Inc., licensed under the Apache
// License, Version 2.0 (LICENSE-codenotary-merkletree; see NOTICE).

package main

// The prose sections of the fixture. Counts are filled in from the build.

import (
	"fmt"
	"strings"
)

func sources() []string {
	return []string{
		"go.mod:1-5 module github.com/codenotary/merkletree, go 1.13; no dependency outside the standard library except testify for tests",
		"LICENSE:1-201 Apache License 2.0; every .go file carries the header Copyright 2019-2020 vChain, Inc.",
		"tree.go:24-28 LeafPrefix = 0x00, NodePrefix = 0x01",
		"mth.go:26-45 MTH: SHA-256(\"\") for no inputs, SHA-256(0x00 || d) for one, else SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])) with k = 1 << (bits.Len64(n-1) - 1), the largest power of two smaller than n",
		"mth.go:50-71 MPath: PATH(m, D[n]) bottom to top; nil for m >= n, empty for n == 1",
		"tree.go:41-47 Root (SHA-256(\"\") for an empty store); tree.go:50-52 LeafHash; tree.go:56-90 Append / AppendHash (incremental store; AppendHash of two hashes into an empty store is how this fixture has the module compute a node hash of two given hashes)",
		"tree.go:125-150 mthAt and tree.go:154-186 InclusionProof(store, at, i): the path for leaf i of the tree of size at+1 (nil when at < 1)",
		"tree.go:192-215 Path.VerifyInclusion(at, i, root, leaf) with at = tree_size - 1: the verifier behind every \"valid\" here, and the source of both discrepancies",
		"store.go:41-75 memStore, NewMemStore (the in-memory Storer)",
		"data_test.go:23-89 testRoots: 65 hard-coded roots, tree sizes 1..65",
		"data_test.go:91-213 testPaths: 45 hard-coded audit paths, every leaf of tree sizes 1..9",
		"mth_test.go:28-37 TestMTH: MTH([]) == SHA-256(\"\") (line 31); MTH of decimal ASCII leaves \"0\"..\"i\" (line 33) == testRoots[i] (line 35)",
		"mth_test.go:39-61 TestMPath: MPath(i, D) == testPaths[index][i] (line 58); MPath is nil outside 0 <= m < n (lines 43, 49)",
		"tree_test.go:46-60 TestAppend: Root of the incremental store == testRoots[index] (line 58)",
		"tree_test.go:62-69 TestRoot: Root(empty store) == SHA-256(\"\") (line 64); Root of the 1-leaf store of \"some value\" == LeafHash(\"some value\") (lines 66-68)",
		"tree_test.go:87-118 TestInclusionProof: InclusionProof(s, at, i) == MPath(i, D[0:at+1]) for every at <= index <= 64, and nil out of range",
		"tree_test.go:120-146 TestVerifyInclusion: 4 edge verdicts on an empty path with an all-zero leaf and root (lines 123-127), then VerifyInclusion(at, i, testRoots[at], leaf i) true for every leaf of sizes 1..65 over MPath paths (lines 131-145)",
		"example_test.go:43-70 make7leaves: the 7-leaf tree over \"d0\"..\"d6\" with named nodes a..l and hash",
		"example_test.go:72-108 TestInclusionPath: InclusionProof(s, 6, i) for i = 0, 3, 4, 6 equals MPath and the named nodes; VerifyInclusion asserted true for i = 0, 3, 6 (lines 82, 91, 107)",
		"data_test.go:215-252 testCPaths, mth.go:73-109 MProof, tree.go:220-330 ConsistencyProof / VerifyConsistency, tree_test.go:148-219, example_test.go:110-143: consistency proofs; the schema has no section for them, not used",
	}
}

func discrepancies(st *buildStats) []string {
	return []string{
		fmt.Sprintf("Right-edge truncated paths (%d cases, sizes 1..32, names starting \"generated: DISCREPANCY right-edge truncated path\"). "+
			"merkletree.Path.VerifyInclusion (tree.go:192-215) consumes one path element per level, halving i and at each time, and returns at == i && h == root (line 214). "+
			"It never checks that the path reached the top of the tree, which RFC 9162 section 2.1.3.2 step 5 does with sn == 0. "+
			"A proper prefix of length L >= 1 of the valid path for leaf m of a tree of size n therefore passes exactly when (m >> L) == ((n - 1) >> L) and the root supplied is the hash the verifier then holds, "+
			"which is the MTH of the right-edge subtree the prefix commits to (leaves a..n-1 for some a > 0). "+
			"Of the %d proper prefixes of every MPath in sizes 1..32, the module accepts %d (all written here) and rejects %d (the %d of leaf 0 are written as \"truncation control\" cases, rejected by both). "+
			"RFC 9162 rejects all %d accepted ones, so each has valid true (the module's verdict), rfc9162_valid false and upstream_expectation none, since no upstream test tries a short path. "+
			"First case: leaf 2 of size 4, path [leaf hash of \"3\"], root d51f2dfecb59566dabdbb6b40bf651cdf39e677b4425165e217590ff3e010edb = node(leaf hash of \"2\", leaf hash of \"3\"). "+
			"Effect: the module accepts a (tree_size, root) pair whose root is a subtree hash rather than the MTH of a tree of that size.",
			st.truncAccepted, st.truncAccepted+st.truncRejectedAll, st.truncAccepted, st.truncRejectedAll, st.truncControl, st.truncAccepted),
		fmt.Sprintf("Over-long paths (%d cases, one per leaf of sizes 1..32, names starting \"generated: DISCREPANCY over-long path\"). "+
			"Once a valid path is consumed, i == at holds and stays true, and tree.go:199-212 keeps hashing every further element in as a left sibling; nothing bounds the path length. "+
			"So the valid path plus any extra elements passes when the root supplied is the resulting hash. "+
			"Each case appends one element, the leaf hash of \"0\", to MPath(m, D[0:n]) and supplies root = node(leaf hash of \"0\", testRoots[n-1]); the module accepts all %d. "+
			"RFC 9162 section 2.1.3.2 step 4a fails the proof because sn is already 0 when the extra element is reached, so each has valid true, rfc9162_valid false and upstream_expectation none. "+
			"For n = 1 the valid path is empty and the extra element is hashed as node(extra, leaf).",
			st.extended, st.extended),
	}
}

func notes(st *buildStats) string {
	parts := []string{
		"Module and version: github.com/codenotary/merkletree (vChain, Inc., Apache-2.0) has three releases, v0.1.0 (2020-02-13), v0.1.1 (2020-02-14) and v0.1.2 (2020-09-16); v0.1.2 is the latest and the one used. " +
			"It is its own RFC 6962 code (a recursive reference MTH / MPath in mth.go and an incremental store with InclusionProof and Path.VerifyInclusion in tree.go), not a wrapper around another library. " +
			"Its full upstream test suite passes under Go 1.26.8.",
		"Conformance: the tree and path are RFC 9162 section 2.1 exactly. All 65 testRoots equal an RFC 9162 MTH computed by reference.go over the same leaves; merkletree.MTH and the incremental store (Append / Root) both reproduce them; " +
			"all 45 testPaths equal the RFC 9162 PATH, and MPath reproduces them; InclusionProof on the 65-leaf store equals MPath for all 2145 (size, leaf) pairs of sizes 1..65; the empty root is SHA-256(\"\"). " +
			"The only departure is in the verifier and is recorded under discrepancies. deviations is empty because no hash, root or generated path differs from RFC 9162.",
		"Verifier conventions: Path.VerifyInclusion(at, i, root, leaf) takes at = tree_size - 1, i = leaf_index, the 32-byte leaf hash (not leaf data) and the path bottom to top as fixed [32]byte values. " +
			"Every inclusion case here is checked as VerifyInclusion(tree_size - 1, leaf_index, root, leaf_hash). Because hashes are fixed-size arrays, no case can carry a wrong-length hash, and tree_size 0 cannot be expressed (at would wrap to 2^64 - 1), so neither appears.",
		"Why the two discrepancy classes are the whole difference: for a path of exactly the RFC 9162 length, the module's per-element choice (sibling on the left when i is odd or i == at) is the RFC's (LSB(fn) set or fn == sn), " +
			"because both start from the same values and diverge only after fn == sn, from which point both put every remaining sibling on the left; so the two verdicts agree on every exact-length path for every tree size. " +
			"A path of any other length is always rejected by RFC 9162, and the module accepts it exactly when at == i after the last element and the root matches: a right-edge prefix, or any extension of a valid path. " +
			"The build checks the at == i rule against the module's verdict for every prefix it tries.",
		"How the discrepancy cases are built: every path is the module's own MPath over the decimal ASCII leaves; a truncated case keeps its first L elements and supplies the MTH (merkletree.MTH) of the subtree PATH(m, D[n]) reaches after L steps, " +
			"which is the only root the verifier could accept for that prefix; an over-long case supplies node(leaf hash of \"0\", testRoots[n-1]), computed by the module (merkletree.AppendHash of the two hashes into an empty store, then Root, because the module exports no node-hash function). " +
			fmt.Sprintf("The counts, %d accepted truncations and %d accepted over-long paths in sizes 1..32, match a separate count made by emulating the verifier loop (257 and 528).", st.truncAccepted, st.extended),
		"Leaf data: the 65 testRoots trees use leaf_data_rule {\"encoding\": \"decimal_ascii\", \"first\": 0}: leaf i is the ASCII decimal digits of i with no padding or terminator (strconv.FormatUint(i, 10), mth_test.go:33, tree_test.go:51, 92, 132), so \"0\", \"1\", ..., \"64\". " +
			"The make7leaves tree lists its 2-byte leaf data \"d0\"..\"d6\", and the TestRoot tree lists \"some value\". No leaf datum is 32 bytes, so a library whose public API takes only 32-byte leaf data can hold these cases only through leaf hashes.",
		"Published versus generated: an inclusion case is \"published\" when its path and root are data_test.go literals (the 45 testPaths) or all its inputs are upstream literals (the 4 edge verdicts at tree_test.go:123-127, all-zero 32-byte leaf and root, empty path). " +
			"Everything else is \"generated\": the TestVerifyInclusion loop cases (published root and an upstream-asserted verdict, but the path comes from MPath), the make7leaves cases, the truncation controls and the discrepancy cases. " +
			"hash_checks: 9 leaf hashes of \"0\"..\"8\", each a data_test.go literal; 1 computed leaf hash (\"some value\"); 64 node hashes whose output is testRoots[n-1] and whose left child is testRoots[k-1], both literals, with the right child a literal for n <= 9 and computed by merkletree.MTH otherwise.",
		fmt.Sprintf("Subset: TestVerifyInclusion (tree_test.go:131-145) calls VerifyInclusion %d times, once per (size, leaf) per store width, and every repeat has identical inputs (checked), so it holds %d distinct cases. "+
			"Written: the 45 of sizes 1..9 (as the published testPaths cases), and %d of sizes 10..65: every leaf of sizes 10..32 (the discrepancy range, so each discrepancy has its valid baseline) and leaves 0, k-1, k and n-1 of sizes 33..65, k being the largest power of two smaller than n. "+
			"The other cases are left out to stay under the 1.5 MB budget; loopKeep in main.go selects them and changing it regenerates any of them.",
			st.loopUnique+st.loopCallsDeduplicated, st.loopUnique, st.loopKept),
		"Upstream expectations: every VerifyInclusion call in the copied upstream tests is followed by an assertion, and all " +
			fmt.Sprintf("%d hold against v0.1.2, so no case has an upstream expectation that differs from the module's verdict. ", st.upstreamCallsRecorded) +
			"The one make7leaves case whose path upstream asserts without verifying it (leaf 4, example_test.go:94-99) has upstream_expectation none.",
		"Provenance and re-running: in the truestamp_merkle repository this file is vectors/interop/codenotary-merkletree.json, and the program that writes and checks it is interop/go/codenotary-merkletree/, a standalone Go module (go 1.26) that requires only github.com/codenotary/merkletree v0.1.2. " +
			"Its testdata/ holds verbatim copies of data_test.go, tree_test.go, mth_test.go and example_test.go, and LICENSE-codenotary-merkletree is the module's LICENSE, all pinned by SHA-256; upstream_data.go compiles data_test.go:23-214 verbatim and upstream_tests.go compiles eight upstream test functions verbatim, and both are checked byte for byte against testdata/ on every run. " +
			"The copied tests run against the real module through thin wrappers (shims.go) and stand-ins for testing, testify/assert and fmt (internal/), which record each VerifyInclusion call and the verdict upstream asserts for it. " +
			"`go run . -fixtures <path>` (the flag is required) rebuilds the fixture, requires the file to be byte-identical, and independently re-derives every value in the file with the module's functions; `-write` regenerates the file first; `-ours <path>` also checks truestamp_merkle's own vectors/merkle.json with the module's functions. " +
			"To regenerate this file, run `go run . -fixtures ../../../vectors/interop/codenotary-merkletree.json -write` from the program directory. The program reads nothing outside its module directory except the -fixtures and -ours paths.",
		"Not included: consistency proofs (testCPaths, MProof, ConsistencyProof, VerifyConsistency), TestIsFrozen and TestPrint, which the schema has no place for.",
	}
	return strings.Join(parts, "\n\n")
}
