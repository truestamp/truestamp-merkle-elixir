// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
// Contains error texts quoted from golang.org/x/mod@v0.41.0 (sumdb/client.go,
// sumdb/client_test.go, sumdb/tlog/tile.go) and follows the call sequence of
// sumdb/client.go and of addRecord in sumdb/client_test.go, BSD-3-Clause,
// Copyright 2009 The Go Authors; see LICENSE-golang-x-mod and NOTICE.

package main

// The sumdb client path. Upstream's client tests never call tlog.CheckRecord.
// They assert inclusion through sumdb.Client, which authenticates a record's
// hash by reading it through tlog.TileHashReader, whose tiles must hash to the
// signed tree hash (sumdb/tlog/tile.go:270-278 and 398-417). Client.checkRecord
// (sumdb/client.go:479-495) reads stored hash StoredHashIndex(0, id) that way
// from the client's latest tree and compares it with RecordHash(data), and
// checkTrees (client.go:430-476) computes TreeHash(older.N) through the tiles
// of the newer tree and compares it with the older signed hash.
//
// This file replays the lookups the client tests make with those tlog
// functions and nothing else: the test log's tiles are built the way addRecord
// publishes them (client_test.go:402-411: tlog.NewTiles and tlog.ReadTileData
// after each record, tile height 2), and each lookup runs the client's steps:
// Client init (client.go:145-161, then the second mergeLatest pass at
// client.go:320-333, which checks the configured tree against itself),
// mergeLatest (client.go:389-423) and checkRecord. What each replayed lookup
// establishes becomes the upstream_expectation of the matching inclusion case:
// "valid" where upstream requires the lookup to succeed, "invalid" where it
// requires the client to reject the tree, and "none" for every other proof.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// tileStore is a test log's published tiles, keyed by tlog.Tile.Path(). It
// implements tlog.TileReader.
type tileStore struct {
	height int
	tiles  map[string][]byte
}

// newTileStore appends the leaves one at a time and publishes the tiles each
// append creates, as addRecord does.
func newTileStore(height int, leaves []tlog.Hash) (*tileStore, error) {
	ts := &tileStore{height: height, tiles: map[string][]byte{}}
	var s storage
	for i, h := range leaves {
		id := int64(i)
		hs, err := tlog.StoredHashesForRecordHash(id, h, s)
		if err != nil {
			return nil, err
		}
		s = append(s, hs...)
		for _, t := range tlog.NewTiles(height, id, id+1) {
			data, err := tlog.ReadTileData(t, s)
			if err != nil {
				return nil, err
			}
			ts.tiles[t.Path()] = data
		}
	}
	return ts, nil
}

func (ts *tileStore) Height() int { return ts.height }

// ReadTiles serves each requested tile. A partial tile that is not stored is
// served as the prefix of its full tile, the fallback of client.go:582-595.
func (ts *tileStore) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		if d, ok := ts.tiles[t.Path()]; ok {
			out[i] = d
			continue
		}
		full := t
		full.W = 1 << uint(t.H)
		if d, ok := ts.tiles[full.Path()]; ok && t.W >= 0 && len(d) >= t.W*tlog.HashSize {
			out[i] = d[:t.W*tlog.HashSize]
			continue
		}
		return nil, fmt.Errorf("no tile %s", t.Path())
	}
	return out, nil
}

func (ts *tileStore) SaveTiles([]tlog.Tile, [][]byte) {}

var errSecurity = errors.New("SECURITY ERROR: the older signed tree is not a prefix of the newer one")

// checkTrees is the check of client.go:430-442: TreeHash(older.N) read
// through the tiles of newer must equal older.Hash.
func checkTrees(ts *tileStore, older, newer tlog.Tree) error {
	h, err := tlog.TreeHash(older.N, tlog.TileHashReader(newer, ts))
	if err != nil {
		return err
	}
	if h != older.Hash {
		return errSecurity
	}
	return nil
}

// checkRecord is the check of client.go:479-495.
func checkRecord(ts *tileStore, latest tlog.Tree, id int64, leaf tlog.Hash) error {
	if id < 0 || id >= latest.N {
		return fmt.Errorf("cannot validate record %d in tree of size %d", id, latest.N)
	}
	hashes, err := tlog.TileHashReader(latest, ts).ReadHashes([]int64{tlog.StoredHashIndex(0, id)})
	if err != nil {
		return err
	}
	if len(hashes) != 1 || hashes[0] != leaf {
		return fmt.Errorf("cannot authenticate record data in server response")
	}
	return nil
}

// clientLog names one test log: a sequence of records that a test client
// serves.
type clientLog string

const (
	logTest   clientLog = "newTestClient"                  // records 0..3, client_test.go:295-309
	logTc     clientLog = "TestClientFork tc"              // records 0..3, then tc's records 4..5 (client_test.go:99-102)
	logTc2    clientLog = "TestClientFork tc2"             // records 0..3, then tc2's records 4..5 (client_test.go:105-108)
	logUnauth clientLog = "TestRejectUnauthenticatedLines" // records 0..3, then the record at client_test.go:195
)

// lookupStep is one Client.Lookup: the response carries record id and the
// signed tree of size respSize from respLog (always the client's own log,
// except for the forked response of client_test.go:111-114).
type lookupStep struct {
	respLog  clientLog
	respSize int64
	id       int64
	where    string
	security bool // upstream requires this lookup to stop at checkTrees with ErrSecurity
}

// clientRun is one sumdb.Client from creation (tc.newClient) through its
// lookups.
type clientRun struct {
	log       clientLog
	startSize int64  // the signed tree in the client's configuration when it is created
	zeroStart bool   // that tree's hash is tlog.Hash{} (TestClientBadTiles, client_test.go:83-92)
	where     string // the line of the first lookup, where Client init runs
	steps     []lookupStep
}

// clientRuns replays every sumdb.Client in client_test.go whose outcome turns on
// a tree or record hash. The lookups over TestClientBadTiles' flipped tiles
// (lines 66-70 and 75-78) and TestClientGONOSUMDB (lines 158-190) test tile
// corruption and path filtering, not hashes, and are left out; the lookups
// that follow the flips (lines 73 and 81) are kept.
var clientRuns = []clientRun{
	{log: logTest, startSize: 1, where: "TestClientLookup client_test.go:30", steps: []lookupStep{
		{respLog: logTest, respSize: 3, id: 2, where: "TestClientLookup client_test.go:30-31"},
		{respLog: logTest, respSize: 1, id: 0, where: "TestClientLookup client_test.go:42-43"},
		{respLog: logTest, respSize: 4, id: 3, where: "TestClientLookup client_test.go:49-50"},
	}},
	{log: logTest, startSize: 1, where: "TestClientBadTiles client_test.go:73", steps: []lookupStep{
		{respLog: logTest, respSize: 3, id: 2, where: "TestClientBadTiles client_test.go:72-73"},
	}},
	{log: logTest, startSize: 3, where: "TestClientBadTiles client_test.go:81", steps: []lookupStep{
		{respLog: logTest, respSize: 4, id: 3, where: "TestClientBadTiles client_test.go:80-81"},
	}},
	{log: logTest, startSize: 1, zeroStart: true, where: "TestClientBadTiles client_test.go:83-92"},
	{log: logTc, startSize: 1, where: "TestClientFork client_test.go:103", steps: []lookupStep{
		{respLog: logTc, respSize: 5, id: 4, where: "TestClientFork client_test.go:103"},
	}},
	{log: logTc2, startSize: 1, where: "TestClientFork client_test.go:109", steps: []lookupStep{
		{respLog: logTc2, respSize: 6, id: 5, where: "TestClientFork client_test.go:109"},
		{respLog: logTc, respSize: 5, id: 4, where: "TestClientFork client_test.go:111-114", security: true},
	}},
	{log: logUnauth, startSize: 1, where: "TestRejectUnauthenticatedLines client_test.go:232", steps: []lookupStep{
		{respLog: logUnauth, respSize: 5, id: 4, where: "TestRejectUnauthenticatedLines client_test.go:232-235"},
	}},
}

// clientSource is what the replay needs: each log's leaf hashes (as many as
// are known) and the signed tree hashes it serves, by tree size.
type clientSource struct {
	leaves map[clientLog][]tlog.Hash
	roots  map[clientLog]map[int64]tlog.Hash
}

// statement is "leaf id of the tree of this size and hash".
type statement struct {
	size int64
	root tlog.Hash
	id   int64
}

// clientVerdicts maps each statement a replayed lookup settles to what
// upstream requires, with the upstream lines that require it.
type clientVerdicts struct {
	valid   map[statement][]string
	invalid map[statement][]string
	checks  int // tlog calls made by the replay
}

func (v clientVerdicts) expectation(size int64, root tlog.Hash, id int64) (string, []string) {
	k := statement{size, root, id}
	if w, ok := v.valid[k]; ok {
		return "valid", w
	}
	if w, ok := v.invalid[k]; ok {
		return "invalid", w
	}
	return "none", nil
}

// replayClients runs every clientRun against src.
func replayClients(src clientSource) (clientVerdicts, error) {
	v := clientVerdicts{valid: map[statement][]string{}, invalid: map[statement][]string{}}
	stores := map[clientLog]*tileStore{}
	for log, leaves := range src.leaves {
		ts, err := newTileStore(clientTileHeight, leaves)
		if err != nil {
			return v, fmt.Errorf("%s tiles: %v", log, err)
		}
		stores[log] = ts
	}
	tree := func(log clientLog, size int64) (tlog.Tree, error) {
		h, ok := src.roots[log][size]
		if !ok {
			return tlog.Tree{}, fmt.Errorf("no signed tree of size %d for %s", size, log)
		}
		return tlog.Tree{N: size, Hash: h}, nil
	}
	empty, err := tlog.TreeHash(0, nil)
	if err != nil {
		return v, err
	}
	for _, run := range clientRuns {
		ts, ok := stores[run.log]
		if !ok {
			return v, fmt.Errorf("%s: no leaves for %s", run.where, run.log)
		}
		start, err := tree(run.log, run.startSize)
		if err != nil {
			return v, fmt.Errorf("%s: %v", run.where, err)
		}
		if run.zeroStart {
			start.Hash = tlog.Hash{}
		}
		// Client init: the in-memory latest starts as the empty tree
		// (client.go:145-151); mergeLatest moves it to the configured tree,
		// then checks that tree against itself (client.go:320-333, 392).
		if err := checkTrees(ts, tlog.Tree{N: 0, Hash: empty}, start); err != nil {
			return v, fmt.Errorf("%s: init, checkTrees(tree#0, tree#%d): %v", run.where, start.N, err)
		}
		err = checkTrees(ts, start, start)
		v.checks += 2
		if run.zeroStart {
			if err == nil || !strings.Contains(err.Error(), "downloaded inconsistent tile") {
				return v, fmt.Errorf("%s: a signed tree#%d with hash tlog.Hash{} gave %v, upstream requires \"downloaded inconsistent tile\"", run.where, start.N, err)
			}
			// The signed tree's only leaf is record 0 (client_test.go:295-298).
			k := statement{start.N, start.Hash, 0}
			v.invalid[k] = append(v.invalid[k], "Client init rejects the signed tree#1 with hash tlog.Hash{} (\"checking tree#1: downloaded inconsistent tile\") at "+run.where)
			continue
		}
		if err != nil {
			return v, fmt.Errorf("%s: init, checkTrees(tree#%d, tree#%d): %v", run.where, start.N, start.N, err)
		}
		if start.N == 1 {
			// TreeHash(1) through the tile is record 0's stored hash, so
			// this check is the statement "record 0 is leaf 0 of tree#1".
			k := statement{1, start.Hash, 0}
			v.valid[k] = append(v.valid[k], run.where)
		}
		latest := start
		for _, st := range run.steps {
			resp, err := tree(st.respLog, st.respSize)
			if err != nil {
				return v, fmt.Errorf("%s: %v", st.where, err)
			}
			// mergeLatest, client.go:389-404.
			if resp.N > latest.N {
				err = checkTrees(ts, latest, resp)
				if err == nil {
					latest = resp
				}
			} else {
				err = checkTrees(ts, resp, latest)
			}
			v.checks++
			if st.security {
				if err != errSecurity {
					return v, fmt.Errorf("%s: checkTrees gave %v, upstream requires ErrSecurity", st.where, err)
				}
				continue
			}
			if err != nil {
				return v, fmt.Errorf("%s: checkTrees: %v", st.where, err)
			}
			leaves := src.leaves[st.respLog]
			if st.id < 0 || st.id >= int64(len(leaves)) {
				return v, fmt.Errorf("%s: no record %d in %s", st.where, st.id, st.respLog)
			}
			if err := checkRecord(ts, latest, st.id, leaves[st.id]); err != nil {
				return v, fmt.Errorf("%s: checkRecord(%d) in tree#%d: %v", st.where, st.id, latest.N, err)
			}
			v.checks++
			k := statement{latest.N, latest.Hash, st.id}
			v.valid[k] = append(v.valid[k], "Client.checkRecord at "+st.where)
		}
	}
	return v, nil
}

// assertionSuffix is appended to the name of a case whose expectation comes
// from a replayed lookup.
func assertionSuffix(where []string) string {
	var init, rec []string
	for _, w := range where {
		switch {
		case strings.HasPrefix(w, "Client.checkRecord at "):
			rec = append(rec, strings.TrimPrefix(w, "Client.checkRecord at "))
		case strings.HasPrefix(w, "Client init rejects"):
			return "; upstream asserts the rejection through sumdb.Client: " + w
		default:
			init = append(init, w)
		}
	}
	sort.Strings(init)
	var parts []string
	if len(rec) > 0 {
		parts = append(parts, "Client.checkRecord (sumdb/client.go:479-495) authenticates this record through tiles of the client's latest tree, which is this tree, at "+strings.Join(rec, " and "))
	}
	if len(init) > 0 {
		parts = append(parts, "Client init authenticates the configured signed tree#1 through its one tile (sumdb/client.go:153-161, 320-333 and 430-442; sumdb/tlog/tile.go:398-417), which holds this record's hash, before the first lookup at "+strings.Join(init, ", "))
	}
	return "; upstream asserts it through sumdb.Client: " + strings.Join(parts, "; ")
}
