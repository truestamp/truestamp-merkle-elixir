// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains literals copied from github.com/transparency-dev/tessera@v1.0.4
// testdata/build_log.sh and internal/witness/witness_test.go, and from
// github.com/transparency-dev/serverless-log@v0.0.0-20260922103222-068d1cc47e5e
// testdata/build_log.sh and testdata/log.go (all Apache-2.0). License texts:
// LICENSE-tessera and LICENSE-serverless-log; see NOTICE.

package main

// The transparency-dev golden test log, published twice: tessera v1.0.4
// testdata/log (tlog-tiles layout, signed by example.com/log/testdata) and
// serverless-log testdata/log (serverless layout, signed by astra). Both were
// built by the same build_log.sh loop over the same 15 leaves, so they carry
// the same 16 roots under different signatures.

import (
	"bytes"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	slapi "github.com/transparency-dev/serverless-log/api"
	sllayout "github.com/transparency-dev/serverless-log/api/layout"
	tapi "github.com/transparency-dev/tessera/api"
	tlayout "github.com/transparency-dev/tessera/api/layout"
	"golang.org/x/mod/sumdb/note"
)

// Copied from github.com/transparency-dev/tessera@v1.0.4 testdata/build_log.sh:20,
// which is byte-identical to github.com/transparency-dev/serverless-log@v0.0.0-20260922103222-068d1cc47e5e
// testdata/build_log.sh:19. Both Apache-2.0. The loop writes each word with
// `echo -n` (no newline), so each leaf's data is exactly the word.
const goldenLeavesLine = "for i in one two three four five six seven eit nain ten ileven twelf threeten fourten fivten; do"

// Copied from github.com/transparency-dev/tessera@v1.0.4 testdata/build_log.sh:11
// (also internal/witness/witness_test.go:42 logVkey), Apache-2.0. The origin is
// the key's name: tessera internal/witness/witness_test.go:588-600 parses
// checkpoint.N with log.ParseCheckpoint(cp, logVerifier.Name(), logVerifier).
const (
	tesseraLogPublicKey = "example.com/log/testdata+33d7b496+AeHTu4Q3hEIMHNqc6fASMsq3rKNx280NI+oO5xCFkkSx"
	tesseraOrigin       = "example.com/log/testdata"
)

// Copied from github.com/transparency-dev/serverless-log@v0.0.0-20260922103222-068d1cc47e5e
// testdata/log.go:33 (TestLogPublicKey) and :35 (TestLogOrigin), Apache-2.0;
// serverless-log client/client_test.go:51-73 parses checkpoint.N with them.
const (
	serverlessLogPublicKey = "astra+cad5a3d2+AZJqeuyE/GnknsCNh1eCtDtwdAwKBddOlS8M2eI1Jt4b"
	serverlessLogOrigin    = "example.com/testdata"
)

const (
	tesseraLogDir    = "tessera/testdata/log"
	serverlessLogDir = "serverless-log/testdata/log"
)

type goldenResult struct {
	leaves     [][]byte
	leafHashes [][]byte
	roots      [][]byte // roots[n] is the signed root at size n
}

func (b *builder) golden() goldenResult {
	var g goldenResult

	// The scripts and the key file must still say what the literals above say.
	tScript := string(readVendored("tessera/testdata/build_log.sh"))
	sScript := string(readVendored("serverless-log/testdata/build_log.sh"))
	logGo := string(readVendored("serverless-log/testdata/log.go"))
	b.expect(strings.Contains(tScript, "\n"+goldenLeavesLine+"\n"), "tessera build_log.sh no longer has the leaves loop")
	b.expect(strings.Contains(sScript, "\n"+goldenLeavesLine+"\n"), "serverless-log build_log.sh no longer has the leaves loop")
	b.expect(strings.Contains(tScript, `echo -n "$i" > ${LEAF}`), "tessera build_log.sh no longer writes leaves with echo -n")
	b.expect(strings.Contains(sScript, `echo -n "$i" > ${LEAF}`), "serverless-log build_log.sh no longer writes leaves with echo -n")
	b.expect(strings.Contains(tScript, `export LOG_PUBLIC_KEY="`+tesseraLogPublicKey+`"`), "tessera build_log.sh public key changed")
	b.expect(strings.Contains(sScript, `export SERVERLESS_LOG_PUBLIC_KEY="`+serverlessLogPublicKey+`"`), "serverless-log build_log.sh public key changed")
	b.expect(strings.Contains(sScript, `export ORIGIN="`+serverlessLogOrigin+`"`), "serverless-log build_log.sh origin changed")
	b.expect(strings.Contains(logGo, `TestLogPublicKey = "`+serverlessLogPublicKey+`"`), "serverless-log log.go TestLogPublicKey changed")
	b.expect(strings.Contains(logGo, `TestLogOrigin = "`+serverlessLogOrigin+`"`), "serverless-log log.go TestLogOrigin changed")

	for _, w := range strings.Fields(strings.TrimSuffix(strings.TrimPrefix(goldenLeavesLine, "for i in "), "; do")) {
		g.leaves = append(g.leaves, []byte(w))
	}
	b.expect(len(g.leaves) == 15, "expected 15 golden leaves, got %d", len(g.leaves))
	n := len(g.leaves)

	// tessera entry bundles tile/entries/000.p/1..15, parsed with tessera's own api.EntryBundle.
	for p := 1; p <= n; p++ {
		var eb tapi.EntryBundle
		if err := eb.UnmarshalText(readVendored(path.Join(tesseraLogDir, tlayout.EntriesPath(0, uint8(p))))); err != nil {
			b.fail("tessera entry bundle 000.p/%d: %v", p, err)
			continue
		}
		b.expect(len(eb.Entries) == p, "tessera entry bundle 000.p/%d has %d entries", p, len(eb.Entries))
		for i := 0; i < p && i < len(eb.Entries); i++ {
			b.expect(bytes.Equal(eb.Entries[i], g.leaves[i]), "tessera entry bundle 000.p/%d entry %d is %q, build_log.sh says %q", p, i, eb.Entries[i], g.leaves[i])
		}
	}

	// tessera level-0 hash tiles tile/0/000.p/1..15, parsed with tessera's own api.HashTile.
	for p := 1; p <= n; p++ {
		var ht tapi.HashTile
		if err := ht.UnmarshalText(readVendored(path.Join(tesseraLogDir, tlayout.TilePath(0, 0, uint8(p))))); err != nil {
			b.fail("tessera hash tile 0/000.p/%d: %v", p, err)
			continue
		}
		b.expect(len(ht.Nodes) == p, "tessera hash tile 0/000.p/%d has %d hashes", p, len(ht.Nodes))
		for i := 0; i < p && i < len(ht.Nodes); i++ {
			b.expect(bytes.Equal(ht.Nodes[i], rfc6962.DefaultHasher.HashLeaf(g.leaves[i])), "tessera tile 0/000.p/%d hash %d is not HashLeaf(%q)", p, i, g.leaves[i])
			b.expect(bytes.Equal(ht.Nodes[i], refLeaf(g.leaves[i])), "tessera tile 0/000.p/%d hash %d is not the RFC leaf hash of %q", p, i, g.leaves[i])
		}
		if p == n {
			g.leafHashes = ht.Nodes
		}
	}
	for i, lh := range g.leafHashes {
		b.f.HashChecks = append(b.f.HashChecks, HashCheck{
			Name:     fmt.Sprintf("tessera v1.0.4 testdata/log/tile/0/000.p/15 hash %d: leaf hash of entry %d %q (tile/entries/000.p/15; serverless-log testdata/log/seq entry %d)", i, i, g.leaves[i], i),
			Kind:     "leaf",
			InputHex: sp(hx(g.leaves[i])),
			Hash:     hx(lh),
		})
	}

	// serverless-log seq/ files hold the leaf data by index; leaves/<leaf hash> hold the index (hex).
	for i := range g.leaves {
		d, f := sllayout.SeqPath(serverlessLogDir, uint64(i))
		b.expect(bytes.Equal(readVendored(path.Join(d, f)), g.leaves[i]), "serverless-log seq entry %d differs from build_log.sh", i)
		if i < len(g.leafHashes) {
			d, f = sllayout.LeafPath(serverlessLogDir, g.leafHashes[i])
			raw, err := vendored.ReadFile(path.Join("testdata", d, f))
			if err != nil {
				b.fail("serverless-log has no leaves/ file for leaf %d (%s): %v", i, hx(g.leafHashes[i]), err)
				continue
			}
			idx, err := strconv.ParseUint(string(raw), 16, 64)
			b.expect(err == nil && idx == uint64(i), "serverless-log leaves/%s holds %q, want index %d", hx(g.leafHashes[i]), raw, i)
		}
	}
	leafFiles := 0
	_ = fs.WalkDir(vendored, path.Join("testdata", serverlessLogDir, "leaves"), func(_ string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			leafFiles++
		}
		return nil
	})
	b.expect(leafFiles == n, "serverless-log leaves/ has %d files, want %d", leafFiles, n)

	// serverless-log tiles tile/00/0000/00/00/00.01..0f, parsed with serverless-log's own api.Tile.
	// Nodes are in-order: TileNodeKey(level, index). Internal nodes are published only
	// for complete subtrees; they become node hash checks.
	var full slapi.Tile
	for p := 1; p <= n; p++ {
		d, f := sllayout.TilePath(serverlessLogDir, 0, 0, uint64(p))
		var t slapi.Tile
		if err := t.UnmarshalText(readVendored(path.Join(d, f))); err != nil {
			b.fail("serverless-log tile 00.%02x: %v", p, err)
			continue
		}
		b.expect(t.NumLeaves == uint(p), "serverless-log tile 00.%02x NumLeaves %d", p, t.NumLeaves)
		node := func(level uint, idx uint64) []byte {
			k := slapi.TileNodeKey(level, idx)
			if int(k) < len(t.Nodes) {
				return t.Nodes[k]
			}
			return nil
		}
		for level := uint(0); level < 8; level++ {
			for idx := uint64(0); idx < uint64(n); idx++ {
				h := node(level, idx)
				complete := (idx+1)<<level <= uint64(p)
				if !complete {
					b.expect(len(h) == 0, "serverless-log tile 00.%02x has an incomplete node (level %d, index %d)", p, level, idx)
					continue
				}
				if level == 0 {
					b.expect(int(idx) < len(g.leafHashes) && bytes.Equal(h, g.leafHashes[idx]), "serverless-log tile 00.%02x leaf %d differs from tessera tile", p, idx)
					continue
				}
				l, r := node(level-1, 2*idx), node(level-1, 2*idx+1)
				b.expect(bytes.Equal(h, rfc6962.DefaultHasher.HashChildren(l, r)), "serverless-log tile 00.%02x node (level %d, index %d) is not HashChildren of its children", p, level, idx)
				b.expect(bytes.Equal(h, refNode(l, r)), "serverless-log tile 00.%02x node (level %d, index %d) is not the RFC node hash", p, level, idx)
			}
		}
		if p == n {
			full = t
		}
	}
	for level := uint(1); level < 8; level++ {
		for idx := uint64(0); (idx+1)<<level <= uint64(n); idx++ {
			k, lk, rk := slapi.TileNodeKey(level, idx), slapi.TileNodeKey(level-1, 2*idx), slapi.TileNodeKey(level-1, 2*idx+1)
			b.f.HashChecks = append(b.f.HashChecks, HashCheck{
				Name:  fmt.Sprintf("serverless-log testdata/log/tile/00/0000/00/00/00.0f node (level %d, index %d) = lines %d, %d, %d: MTH of leaves %d..%d", level, idx, 3+lk, 3+rk, 3+k, idx<<level, (idx+1)<<level-1),
				Kind:  "node",
				Left:  sp(hx(full.Nodes[lk])),
				Right: sp(hx(full.Nodes[rk])),
				Hash:  hx(full.Nodes[k]),
			})
		}
	}

	// Signed checkpoints: tessera and serverless-log, sizes 0..15, verified and
	// parsed with transparency-dev/formats log.ParseCheckpoint and the Ed25519 note keys above.
	tv, err := note.NewVerifier(tesseraLogPublicKey)
	if err != nil {
		b.fail("tessera note verifier: %v", err)
		return g
	}
	sv, err := note.NewVerifier(serverlessLogPublicKey)
	if err != nil {
		b.fail("serverless-log note verifier: %v", err)
		return g
	}
	g.roots = make([][]byte, n+1)
	for size := 0; size <= n; size++ {
		rawT := readVendored(fmt.Sprintf("%s/checkpoint.%d", tesseraLogDir, size))
		rawS := readVendored(fmt.Sprintf("%s/checkpoint.%d", serverlessLogDir, size))
		cpT, _, _, errT := log.ParseCheckpoint(rawT, tesseraOrigin, tv)
		cpS, _, _, errS := log.ParseCheckpoint(rawS, serverlessLogOrigin, sv)
		if errT != nil || errS != nil {
			b.fail("checkpoint.%d: tessera %v, serverless-log %v", size, errT, errS)
			continue
		}
		b.expect(cpT.Size == uint64(size) && cpS.Size == uint64(size), "checkpoint.%d sizes %d and %d", size, cpT.Size, cpS.Size)
		b.expect(bytes.Equal(cpT.Hash, cpS.Hash), "checkpoint.%d: tessera and serverless-log roots differ", size)
		b.expect(bytes.Equal(cpT.Hash, tdmRoot(g.leafHashes[:size])), "checkpoint.%d root is not the transparency-dev/merkle root of the first %d leaves", size, size)
		b.expect(bytes.Equal(cpT.Hash, refMTH(g.leafHashes[:size])), "checkpoint.%d root is not the RFC 9162 MTH of the first %d leaves", size, size)
		g.roots[size] = cpT.Hash
	}
	b.expect(bytes.Equal(readVendored(tesseraLogDir+"/checkpoint"), readVendored(tesseraLogDir+"/checkpoint.15")), "tessera checkpoint is not checkpoint.15")
	b.expect(bytes.Equal(readVendored(serverlessLogDir+"/checkpoint"), readVendored(serverlessLogDir+"/checkpoint.15")), "serverless-log checkpoint is not checkpoint.15")
	b.expect(bytes.Equal(g.roots[0], rfc6962.DefaultHasher.EmptyRoot()), "checkpoint.0 root is not SHA-256 of the empty string")
	b.f.EmptyRoot = sp(hx(g.roots[0]))

	for size := 0; size <= n; size++ {
		first := "no leaves"
		if size > 0 {
			first = fmt.Sprintf("leaves %q..%q", g.leaves[0], g.leaves[size-1])
		}
		b.f.Trees = append(b.f.Trees, Tree{
			Name:       fmt.Sprintf("golden log checkpoint.%d (tessera v1.0.4 testdata/log/checkpoint.%d signed by example.com/log/testdata; serverless-log testdata/log/checkpoint.%d signed by astra): signed root at size %d over the build_log.sh %s", size, size, size, size, first),
			LeafData:   hxs(g.leaves[:size]),
			LeafHashes: hxs(g.leafHashes[:size]),
			TreeSize:   uint64(size),
			Root:       hx(g.roots[size]),
		})
	}
	return g
}
