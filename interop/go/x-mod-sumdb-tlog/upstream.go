// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
// Contains literals copied from golang.org/x/mod@v0.41.0 (sumdb/tlog/tlog.go,
// sumdb/tlog/note_test.go, sumdb/tlog/tlog_test.go, sumdb/client_test.go),
// BSD-3-Clause, Copyright 2009 The Go Authors; see LICENSE-golang-x-mod and
// NOTICE.

package main

import "golang.org/x/mod/sumdb/tlog"

// Literals copied verbatim from golang.org/x/mod v0.41.0 (BSD-3-Clause,
// Copyright 2009 The Go Authors; the license text is vendored beside this
// file as LICENSE-golang-x-mod). Every value here is either a hard-coded
// answer from an upstream file, the upstream leaf data those answers were
// computed from, or a parameter of the upstream test that produced them. File
// paths are relative to the module root
// ($(go env GOMODCACHE)/golang.org/x/mod@v0.41.0).

// sumdb/tlog/tlog.go:237-244, the emptyHash literal that TreeHash(0, r)
// returns (tlog.go:250-253). sumdb/tlog/tlog_test.go:272-280 (TestEmptyTree)
// asserts TreeHash(0, nil) == sha256.Sum256(nil).
var upstreamEmptyHash = [32]byte{
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
}

// sumdb/tlog/note_test.go:14-15 (TestFormatTree):
//
//	h := RecordHash([]byte("hello world"))
//	golden := "go.sum database tree\n123456789012\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n"
//
// The same golden hash is parsed back in TestParseTree (note_test.go:23-28)
// and reused as a fuzz seed (note_test.go:121). The tree size 123456789012 in
// that note is a formatting test value, not the size of a real tree, so this
// hash is only usable as a leaf hash known answer.
const (
	noteTestLeafData    = "hello world"
	noteTestLeafHashB64 = "TszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0="
)

// sumdb/client_test.go:295-309 (newTestClient): records 0..3 of the test log,
// added in this order with tc.addRecord (client_test.go:383-412 hashes each
// record with tlog.RecordHash and appends tlog.StoredHashesForRecordHash).
const (
	clientRecord0 = `rsc.io/quote v1.5.2 h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=
rsc.io/quote v1.5.2/go.mod h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=
rsc.io/quote v1.5.2 h2:xyzzy
` // client_test.go:295-298
	clientRecord1 = `golang.org/x/text v0.0.0-20170915032832-14c0d48ead0c h1:qgOY6WgZOaTkIIMiVjBQcw93ERBE4m30iBm00nkL0i8=
golang.org/x/text v0.0.0-20170915032832-14c0d48ead0c/go.mod h1:NqM8EUOU14njkJ3fqMW+pc6Ldnwhi/IjpwHt7yyuwOQ=
` // client_test.go:300-302
	clientRecord2 = `rsc.io/sampler v1.3.0 h1:7uVkIFmeBqHfdjD+gZwtXXI+RODJ2Wc4O7MPEh/QiW4=
rsc.io/sampler v1.3.0/go.mod h1:T1hPZKmBbMNahiBKFy5HrXp6adAjACjK9JXDnKaTXpA=
` // client_test.go:303-305
	clientRecord3 = `rsc.io/Quote v1.5.2 h1:uppercase!=
` // client_test.go:308-309
)

// sumdb/client_test.go:306 (newTestClient), after records 0..2 are added:
//
//	tc.config[testName+"/latest"] = tc.signTree(1)
//
// so the client starts from the signed tree of size 1, whose only leaf is
// record 0.
const clientStartTreeSize = 1 // client_test.go:306, signTree(1)

// sumdb/client_test.go:83-92 (TestClientBadTiles), "Bad starting tree hash
// looks like bad tiles":
//
//	tc.newClient()
//	text := tlog.FormatTree(tlog.Tree{N: 1, Hash: tlog.Hash{}})
//	...
//	tc.mustError(err, "rsc.io/sampler@v1.3.0: initializing sumdb.Client: checking tree#1: downloaded inconsistent tile")
//
// The client is handed a signed tree of size 1 whose hash is the zero value of
// tlog.Hash (32 zero bytes), and upstream requires the lookup to fail. Upstream
// detects it through tile hashes, not CheckRecord.
const badStartTreeSize = 1 // client_test.go:85, N: 1

var badStartTreeHash = tlog.Hash{} // client_test.go:85, Hash: tlog.Hash{}

// sumdb/client_test.go:95-109 (TestClientFork): tc and its fork tc2 each append
// two more records after the four above.
const (
	tcRecord4 = `rsc.io/pkg1 v1.5.2 h1:hash!=
` // client_test.go:99-100 (tc)
	tcRecord5 = `rsc.io/pkg1 v1.5.4 h1:hash!=
` // client_test.go:101-102 (tc)
	tc2Record4 = `rsc.io/pkg1 v1.5.3 h1:hash!=
` // client_test.go:105-106 (tc2)
	tc2Record5 = `rsc.io/pkg1 v1.5.4 h1:hash!=
` // client_test.go:107-108 (tc2)
)

// sumdb/client_test.go:116-139, the recorded SECURITY ERROR text of
// TestClientFork. sumdb/client.go:430-475 (checkTrees) prints, in order:
// the older signed note (tc's tree of size 5), the newer signed note (tc2's
// tree of size 6), then TreeHash(5) as computed from the newer tree, then the
// hashes of tlog.ProveTree(6, 5). client_test.go:141-149 asserts prefixes of
// this text, including "proof of misbehavior:\n\tT7i+H/8ER4nXOiw4Bj0k" at
// line 148.
const (
	forkOldTree5RootB64 = "nWzN20+pwMt62p7jbv1/NlN95ePTlHijabv5zO/s36w=" // client_test.go:123, tc tree size 5
	forkNewTree6RootB64 = "wc4SkQt52o5W2nQ8To2ARs+mWuUJjss+sdleoiqxMmM=" // client_test.go:130, tc2 tree size 6
	forkTc2Tree5RootB64 = "T7i+H/8ER4nXOiw4Bj0koZOkGjkxoNvlI34GpvhHhQg=" // client_test.go:135, TreeHash(5) of tc2
	forkProof0B64       = "Nsuejv72de9hYNM5bqFv8rv3gm3zJQwv/DT/WNbLDLA=" // client_test.go:136, ProveTree(6,5)[0]
	forkProof1B64       = "mOmqqZ1aI/lzS94oq/JSbj7pD8Rv9S+xDyi12BtVSHo=" // client_test.go:137, ProveTree(6,5)[1]
	forkProof2B64       = "/7Aw5jVSMM9sFjQhaMg+iiDYPMk6decH7QLOGrL9Lx0=" // client_test.go:138, ProveTree(6,5)[2]
)

// sumdb/tlog/tlog_test.go:59-149 (TestTree) has no hard-coded answers. It
// appends records fmt.Appendf(nil, "leaf %d", i) for i in 0..99 (lines 65-66),
// computes each tree hash with TreeHash (line 77), and for every tree and leaf
// checks ProveRecord against CheckRecord (lines 134-141), then flips the low
// bit of byte 0 of each proof hash in turn (p[k][0] ^= 1, line 143) and
// requires CheckRecord to fail with "succeeded with corrupt proof hash #%d!"
// (line 145).
const (
	testTreeLeafFormat   = "leaf %d" // tlog_test.go:66
	testTreeMaxSize      = 100       // tlog_test.go:65, trees of size 1..100
	testTreeProofMaxSize = 16        // our choice: proofs and corruptions for sizes 1..16 only
)

// sumdb/client_test.go:278 (newTestClient, tileHeight: 2) and :318
// (newClient, tc.client.SetTileHeight(tc.tileHeight)): the test log publishes
// tiles of height 2 (addRecord, client_test.go:402-411), and the client reads
// and authenticates tiles of that height.
const clientTileHeight = 2 // client_test.go:278

// sumdb/client_test.go:192-239 (TestRejectUnauthenticatedLines): a fifth
// record is appended to newTestClient's four (lines 196-206), the tree of
// size 5 is hashed with tlog.TreeHash (line 209), and the signed note is that
// tree followed by an extra golang.org/x/bad line that no tree hash covers
// (lines 213-214). The lookup of record 4 must succeed (lines 232-235) and
// return no lines (lines 236-238).
const unauthRecord4 = "golang.org/x/good v1.0.0 h1:7uVkIFmeBqHfdjD+gZwtXXI+RODJ2Wc4O7MPEh/QiW4=\n" // client_test.go:195
