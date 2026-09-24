// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains test literals and test bodies copied from
// github.com/cometbft/cometbft@v1.0.1 (Apache-2.0), each block citing its file
// and lines: internal/blocksync/msgs_test.go, types/part_set_test.go,
// types/results_test.go, state/store_test.go and types/tx_test.go. License
// text: LICENSE-cometbft. See NOTICE.

package main

// More copies of upstream test literals and test bodies from
// github.com/cometbft/cometbft v1.0.1, licensed Apache-2.0 (Apache License,
// Version 2.0, LICENSE at the module root). Each block names the file and line
// range it came from; paths are relative to the module root
// ($(go env GOMODCACHE)/github.com/cometbft/cometbft@v1.0.1). Adaptations are
// limited to what a non-test program needs: cmtrand (crypto-seeded) is replaced
// by the deterministic detRand stream, and testify assertions are recorded as
// named checks instead of being reported through *testing.T.

import (
	"bytes"
	"fmt"
	"io"

	"github.com/cosmos/gogoproto/proto"

	abci "github.com/cometbft/cometbft/abci/types"
	bcproto "github.com/cometbft/cometbft/api/cometbft/blocksync/v1"
	"github.com/cometbft/cometbft/crypto/merkle"
	"github.com/cometbft/cometbft/types"
)

// namedCheck is one upstream assertion, recorded instead of reported.
type namedCheck struct {
	what string
	ok   bool
}

// ---------------------------------------------------------------------------
// internal/blocksync/msgs_test.go:79-140 (TestBlocksyncMessageVectors),
// github.com/cometbft/cometbft v1.0.1, Apache-2.0.
// ---------------------------------------------------------------------------

// msgs_test.go:81: the block's only transaction.
var upBlocksyncTxs = []types.Tx{types.Tx("Hello World")}

// msgs_test.go:101-103 "BlockResponseMessage": the expected encoding, verbatim.
// Inside it the Header's data_hash field (tag 0x3a, 32 bytes) is
// c4da88e876062aa1543400d50d0eaa0dac88096057949cfb7bca7f3a48c04bf9 and the
// evidence_hash field (tag 0x6a, 32 bytes) is the empty-tree root.
const upBlocksyncBlockResponseHex = "1a700a6e0a5b0a02080b1803220b088092b8c398feffffff012a0212003a20c4da88e876062aa1543400d50d0eaa0dac88096057949cfb7bca7f3a48c04bf96a20e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855120d0a0b48656c6c6f20576f726c641a00"

// upBlocksyncBlockResponse is msgs_test.go:81-85, 101-103 and 135 verbatim
// (require.NoError replaced by must): the message whose encoding the golden
// vector pins. MakeBlock (types/test_util.go:111-125) fills DataHash with
// Data.Hash() = Txs.Hash() (types/block.go:111-121, 1334-1344; types/tx.go:45-50).
func upBlocksyncBlockResponse() []byte {
	block := types.MakeBlock(int64(3), []types.Tx{types.Tx("Hello World")}, nil, nil)
	block.Version.Block = 11 // overwrite updated protocol version

	bpb, err := block.ToProto()
	must(err)

	bmsg := &bcproto.Message{Sum: &bcproto.Message_BlockResponse{
		BlockResponse: &bcproto.BlockResponse{Block: bpb},
	}}
	bz, _ := proto.Marshal(bmsg)
	return bz
}

// ---------------------------------------------------------------------------
// types/part_set_test.go, github.com/cometbft/cometbft v1.0.1, Apache-2.0.
// ---------------------------------------------------------------------------

// part_set_test.go:15-17: testPartSize = 65536 // 64KB ...  4096 // 4KB
const upTestPartSize = 65536

// part_set_test.go:21 (TestBasicPartSet nParts := 100) and :69 (TestWrongProof
// testPartSize * 100).
const upPartSetParts = 100

// addPartCall is one PartSet.AddPart call made by an upstream test: a deep copy
// of the part exactly as it was passed in, and what AddPart returned.
type addPartCall struct {
	desc  string // upstream's own wording for the case
	lines string // part_set_test.go line range
	part  types.Part
	added bool
	err   error
}

func snapshotPart(p *types.Part) types.Part {
	var aunts [][]byte
	if p.Proof.Aunts != nil {
		aunts = make([][]byte, len(p.Proof.Aunts))
		for i, a := range p.Proof.Aunts {
			aunts[i] = append([]byte(nil), a...)
		}
	}
	return types.Part{
		Index: p.Index,
		Bytes: append([]byte(nil), p.Bytes...),
		Proof: merkle.Proof{
			Total:    p.Proof.Total,
			Index:    p.Proof.Index,
			LeafHash: append([]byte(nil), p.Proof.LeafHash...),
			Aunts:    aunts,
		},
	}
}

// upTestBasicPartSet is part_set_test.go:19-65 (TestBasicPartSet). The body is
// verbatim except: data (line 22, cmtrand.Bytes(testPartSize * nParts)) is a
// parameter, each assertion is recorded, and every part is snapshotted just
// before it is passed to AddPart.
func upTestBasicPartSet(data []byte) (*types.PartSet, []addPartCall, []namedCheck) {
	var checks []namedCheck
	check := func(what string, ok bool) { checks = append(checks, namedCheck{"part_set_test.go " + what, ok}) }

	// Construct random data of size partSize * 100
	nParts := 100
	check("line 22 data length is testPartSize * nParts", len(data) == upTestPartSize*nParts)
	partSet := types.NewPartSetFromData(data, upTestPartSize)

	check("line 25 NotEmpty(partSet.Hash())", len(partSet.Hash()) > 0)
	check("line 26 partSet.Total() == nParts", partSet.Total() == uint32(nParts))
	check("line 27 BitArray().Size() == nParts", partSet.BitArray().Size() == nParts)
	check("line 28 HashesTo(Hash())", partSet.HashesTo(partSet.Hash()))
	check("line 29 IsComplete()", partSet.IsComplete())
	check("line 30 Count() == nParts", partSet.Count() == uint32(nParts))
	check("line 31 ByteSize() == testPartSize*nParts", partSet.ByteSize() == int64(upTestPartSize*nParts))

	// Test adding parts to a new partSet.
	partSet2 := types.NewPartSetFromHeader(partSet.Header())

	check("line 36 HasHeader", partSet2.HasHeader(partSet.Header()))
	var calls []addPartCall
	for i := 0; i < int(partSet.Total()); i++ {
		part := partSet.GetPart(i)
		snap := snapshotPart(part)
		added, err := partSet2.AddPart(part)
		calls = append(calls, addPartCall{fmt.Sprintf("AddPart(partSet.GetPart(%d)) must succeed", i), "37-44", snap, added, err})
		check(fmt.Sprintf("lines 40-43 part %d added without error (err %v)", i, err), added && err == nil)
	}
	// adding part with invalid index
	added, err := partSet2.AddPart(&types.Part{Index: 10000})
	check("lines 46-48 AddPart(&Part{Index: 10000}) fails", !added && err != nil)
	// adding existing part
	added, err = partSet2.AddPart(partSet2.GetPart(0))
	check("lines 50-52 re-adding part 0 returns (false, nil)", !added && err == nil)

	check("line 54 partSet.Hash() == partSet2.Hash()", bytes.Equal(partSet.Hash(), partSet2.Hash()))
	check("line 55 partSet2.Total() == nParts", partSet2.Total() == uint32(nParts))
	check("line 56 ByteSize() == nParts*testPartSize", partSet.ByteSize() == int64(nParts*upTestPartSize))
	check("line 57 partSet2.IsComplete()", partSet2.IsComplete())

	// Reconstruct data, assert that they are equal.
	data2Reader := partSet2.GetReader()
	data2, err := io.ReadAll(data2Reader)
	check("line 62 ReadAll", err == nil)

	check("line 64 data == data2", bytes.Equal(data, data2))
	return partSet, calls, checks
}

// upTestWrongProof is part_set_test.go:67-106 (TestWrongProof). The body is
// verbatim except: data (line 69, cmtrand.Bytes(testPartSize * 100)) is a
// parameter, and each AddPart call is recorded (with a snapshot of the part as
// passed in) instead of being checked with t.Errorf. The four mutations write
// through GetPart's pointer into partSet's own parts, exactly as upstream does.
func upTestWrongProof(data []byte) (*types.PartSet, []addPartCall) {
	// Construct random data of size partSize * 100
	partSet := types.NewPartSetFromData(data, upTestPartSize)

	// Test adding a part with wrong data.
	partSet2 := types.NewPartSetFromHeader(partSet.Header())

	var calls []addPartCall
	record := func(desc, lines string, part *types.Part) {
		snap := snapshotPart(part)
		added, err := partSet2.AddPart(part)
		calls = append(calls, addPartCall{desc, lines, snap, added, err})
	}

	// Test adding a part with wrong trail.
	part := partSet.GetPart(0)
	part.Proof.Aunts[0][0] += byte(0x01)
	record("expected to fail adding a part with bad trail.", "75-81", part)

	// Test adding a part with wrong bytes.
	part = partSet.GetPart(1)
	part.Bytes[0] += byte(0x01)
	record("expected to fail adding a part with bad bytes.", "83-89", part)

	// Test adding a part with wrong proof index.
	part = partSet.GetPart(2)
	part.Proof.Index = 1
	record("expected to fail adding a part with bad proof index.", "91-97", part)

	// Test adding a part with wrong proof total.
	part = partSet.GetPart(3)
	part.Proof.Total = int64(partSet.Total() - 1)
	record("expected to fail adding a part with bad proof total.", "99-105", part)

	return partSet, calls
}

// ---------------------------------------------------------------------------
// types/results_test.go:12-54 (TestABCIResults), github.com/cometbft/cometbft
// v1.0.1, Apache-2.0. Lines 13-18 and 29 verbatim.
// ---------------------------------------------------------------------------

// upABCIResults returns results (line 29) and the two results a and b that
// lines 20-26 require to encode identically (b is left out of results).
func upABCIResults() (results types.ABCIResults, a, b *abci.ExecTxResult) {
	a = &abci.ExecTxResult{Code: 0, Data: nil}
	b = &abci.ExecTxResult{Code: 0, Data: []byte{}}
	c := &abci.ExecTxResult{Code: 0, Data: []byte("one")}
	d := &abci.ExecTxResult{Code: 14, Data: nil}
	e := &abci.ExecTxResult{Code: 14, Data: []byte("foo")}
	f := &abci.ExecTxResult{Code: 14, Data: []byte("bar")}

	// a and b should be the same, don't go in results.
	results = types.ABCIResults{a, c, d, e, f}
	return results, a, b
}

// ---------------------------------------------------------------------------
// state/store_test.go:232-248 (TestTxResultsHash), github.com/cometbft/cometbft
// v1.0.1, Apache-2.0. Lines 233-235 verbatim.
// ---------------------------------------------------------------------------

func upTxResultsHashInput() []*abci.ExecTxResult {
	txResults := []*abci.ExecTxResult{
		{Code: 32, Data: []byte("Hello"), Log: "Huh?"},
	}
	return txResults
}

// ---------------------------------------------------------------------------
// types/tx_test.go, github.com/cometbft/cometbft v1.0.1, Apache-2.0.
// ---------------------------------------------------------------------------

// makeTxs is tx_test.go:16-22 verbatim except that cmtrand.Bytes(size) is
// r.Bytes(size) from the deterministic stream.
func makeTxs(r *detRand, cnt, size int) types.Txs {
	txs := make(types.Txs, cnt)
	for i := 0; i < cnt; i++ {
		txs[i] = r.Bytes(size)
	}
	return txs
}

// tx_test.go:57-59 (TestValidTxProof): {makeTxs(20, 5)}, {makeTxs(7, 81)},
// {makeTxs(61, 15)}.
var upValidTxProofRandomCases = []struct {
	line      string
	cnt, size int
}{
	{"57", 20, 5},
	{"58", 7, 81},
	{"59", 61, 15},
}
