// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains test literals and test helpers copied from
// github.com/cometbft/cometbft@v1.0.1 (Apache-2.0), each block citing its file
// and lines: crypto/merkle/rfc6962_test.go, crypto/merkle/tree_test.go,
// crypto/merkle/proof_test.go, crypto/merkle/proof.go, crypto/merkle/types.go,
// libs/test/mutate.go, abci/types/types_test.go, types/block_test.go,
// types/encoding_helper.go, types/utils.go, types/validator_set_test.go,
// types/consensus_breakage_test.go and types/tx_test.go. The
// crypto/merkle/rfc6962_test.go literals carry the upstream notice "Copyright
// 2016 Google Inc. All Rights Reserved." (taken by cometbft from
// github.com/google/trillian, Apache-2.0). License text: LICENSE-cometbft. See
// NOTICE.

package main

// Verbatim copies of upstream test literals and test helpers from
// github.com/cometbft/cometbft v1.0.1, licensed Apache-2.0 (Apache License,
// Version 2.0, LICENSE at the module root). Test files are not importable, so
// the literals are copied here with the file and line numbers they came from.
// Paths are relative to the module root
// ($(go env GOMODCACHE)/github.com/cometbft/cometbft@v1.0.1).

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"time"

	gogotypes "github.com/cosmos/gogoproto/types"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtversion "github.com/cometbft/cometbft/api/cometbft/version/v1"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/crypto/tmhash"
	"github.com/cometbft/cometbft/libs/bytes"
	"github.com/cometbft/cometbft/types"
)

// ---------------------------------------------------------------------------
// crypto/merkle/rfc6962_test.go:26-76 (TestRFC6962Hasher), copied from Trillian.
// The `want` strings are sliced [:tmhash.Size*2] upstream, i.e. the full 64 hex
// characters.
// ---------------------------------------------------------------------------

// rfc6962_test.go:42 "RFC6962 Empty Tree", got = trailsFromByteSlices([][]byte{}) root.
const upRFC6962EmptyTree = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// rfc6962_test.go:50 "RFC6962 Empty Leaf", got = trailsFromByteSlices([][]byte{{}}) root (line 29).
const upRFC6962EmptyLeaf = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"

// rfc6962_test.go:56 "RFC6962 Leaf", got = trailsFromByteSlices([][]byte{[]byte("L123456")}) root (line 27).
const upRFC6962Leaf = "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56"

var upRFC6962LeafInput = []byte("L123456") // rfc6962_test.go:27

// rfc6962_test.go:62-63 "RFC6962 Node", got = innerHash([]byte("N123"), []byte("N456")).
const upRFC6962Node = "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb"

var (
	upRFC6962NodeLeft  = []byte("N123") // rfc6962_test.go:63
	upRFC6962NodeRight = []byte("N456") // rfc6962_test.go:63
)

// rfc6962_test.go:80 (TestRFC6962HasherCollisions): leaf1, leaf2 := []byte("Hello"), []byte("World").
// The test only asserts inequalities (lines 85, 95, 101); no hash is hard-coded.
var (
	upCollisionLeaf1 = []byte("Hello")
	upCollisionLeaf2 = []byte("World")
)

// ---------------------------------------------------------------------------
// crypto/merkle/tree_test.go:21-42 (TestHashFromByteSlices), lines 26-34.
// Upstream uses a map (random iteration order); listed here in source order.
// ---------------------------------------------------------------------------

type upTreeCase struct {
	name       string
	lines      string
	slices     [][]byte
	expectHash string
}

var upHashFromByteSlicesCases = []upTreeCase{
	{"nil", "26", nil, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"empty", "27", [][]byte{}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"single", "28", [][]byte{{1, 2, 3}}, "054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8"},
	{"single blank", "29", [][]byte{{}}, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
	{"two", "30", [][]byte{{1, 2, 3}, {4, 5, 6}}, "82e6cfce00453804379b53962939eaa7906b39904be0813fcadd31b100773c4b"},
	{"many", "31-34", [][]byte{{1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}}, "f326493eceab4f2d9ffbc78c59432a0a005d6ea98392045c74df5d14a113be18"},
}

// tree_test.go:46-47 (TestProof): ProofsFromByteSlices([][]byte{}) root.
const upTestProofEmptyRoot = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// tree_test.go:50 (TestProof): total := 100, items are testItem(cmtrand.Bytes(tmhash.Size)) (line 54).
const upTestProofTotal = 100

// tree_test.go:136-157 (Test_getSplitPoint), table at lines 141-151.
var upSplitPoints = []struct{ length, want int64 }{
	{1, 0},
	{2, 1},
	{3, 2},
	{4, 2},
	{5, 4},
	{10, 8},
	{20, 16},
	{100, 64},
	{255, 128},
	{256, 128},
	{257, 256},
}

// ---------------------------------------------------------------------------
// crypto/merkle/proof_test.go:142-179 (TestProofValidateBasic).
// ---------------------------------------------------------------------------

// proof_test.go:167-171: the tree whose proofs[0] is malleated.
var upValidateBasicLeaves = [][]byte{
	[]byte("apple"),
	[]byte("watermelon"),
	[]byte("kiwi"),
}

// proof_test.go:148-162: name, malleation (applied to a copy of proofs[0]) and
// the ValidateBasic error the test expects ("" = no error expected).
type upMalleation struct {
	name   string
	line   string
	mutate func(total, index *int64, leafHash *[]byte, aunts *[][]byte)
	errStr string
}

const upMaxAunts = 100 // crypto/merkle/proof.go:17 (MaxAunts)

var upValidateBasicMalleations = []upMalleation{
	{"Good", "148", func(_, _ *int64, _ *[]byte, _ *[][]byte) {}, ""},
	{"Negative Total", "149", func(total, _ *int64, _ *[]byte, _ *[][]byte) { *total = -1 }, "negative proof total"},
	{"Negative Index", "150", func(_, index *int64, _ *[]byte, _ *[][]byte) { *index = -1 }, "negative proof index"},
	{"Invalid LeafHash", "151-154", func(_, _ *int64, leafHash *[]byte, _ *[][]byte) { *leafHash = make([]byte, 10) }, "leaf length 10, want 32"},
	{"Too many Aunts", "155-158", func(_, _ *int64, _ *[]byte, aunts *[][]byte) { *aunts = make([][]byte, upMaxAunts+1) }, "maximum aunts length, 100, exceeded"},
	{"Invalid Aunt", "159-162", func(_, _ *int64, _ *[]byte, aunts *[][]byte) { (*aunts)[0] = make([]byte, 10) }, "aunt#0 hash length 10, want 32"},
}

// ---------------------------------------------------------------------------
// crypto/merkle/proof_test.go:210-231 (TestVsa2022_100; comment line 210, func 211-231).
// ---------------------------------------------------------------------------

// upVsa2022100 returns key, value, kvhash exactly as proof_test.go:213-219 builds them.
func upVsa2022100() (key, value, kvhash []byte) {
	key = []byte{0x13}   // proof_test.go:213
	value = []byte{0x37} // proof_test.go:214
	vhash := tmhash.Sum(value)
	bz := make([]byte, 0)
	bz = appendUvarintPrefixed(bz, key)           // proof_test.go:217 encodeByteSlice(bz, key)
	bz = appendUvarintPrefixed(bz, vhash)         // proof_test.go:218 encodeByteSlice(bz, vhash)
	kvhash = tmhash.Sum(append([]byte{0}, bz...)) // proof_test.go:219
	return key, value, kvhash
}

// appendUvarintPrefixed mirrors crypto/merkle/types.go:30-39 (encodeByteSlice):
// uvarint length prefix followed by the bytes.
func appendUvarintPrefixed(dst, bz []byte) []byte {
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(len(bz)))
	dst = append(dst, buf[0:n]...)
	return append(dst, bz...)
}

// ---------------------------------------------------------------------------
// libs/test/mutate.go:7-28 (MutateByteSlice), used by crypto/merkle/tree_test.go
// TestProof (lines 92, 96) and types/tx_test.go testTxProofUnchangable (line 120).
// Verbatim except that cmtrand.Int() (crypto-seeded, not reproducible) is replaced
// by r.Int() from the deterministic stream below, so the fixture is reproducible.
// ---------------------------------------------------------------------------

// Contract: !bytes.Equal(input, output) && len(input) >= len(output).
func mutateByteSlice(r *detRand, bytez []byte) []byte {
	// If bytez is empty, panic
	if len(bytez) == 0 {
		panic("Cannot mutate an empty bytez")
	}

	// Copy bytez
	mBytez := make([]byte, len(bytez))
	copy(mBytez, bytez)
	bytez = mBytez

	// Try a random mutation
	switch r.Int() % 2 {
	case 0: // Mutate a single byte
		bytez[r.Int()%len(bytez)] += byte(r.Int()%255 + 1)
	case 1: // Remove an arbitrary byte
		pos := r.Int() % len(bytez)
		bytez = append(bytez[:pos], bytez[pos+1:]...)
	}
	return bytez
}

// detRand is a transparent deterministic stand-in for cmtrand: output block k is
// SHA-256(label || uint64be(k)).
type detRand struct {
	label string
	ctr   uint64
}

func (r *detRand) next() [32]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], r.ctr)
	r.ctr++
	return sha256.Sum256(append([]byte(r.label), b[:]...))
}

// Int returns a non-negative int, like cmtrand.Int.
func (r *detRand) Int() int {
	s := r.next()
	return int(binary.BigEndian.Uint64(s[:8]) >> 1)
}

// Bytes returns n bytes, standing in for cmtrand.Bytes(n).
func (r *detRand) Bytes(n int) []byte {
	out := make([]byte, 0, n+32)
	for len(out) < n {
		s := r.next()
		out = append(out, s[:]...)
	}
	return out[:n]
}

// ---------------------------------------------------------------------------
// types/tx_test.go:50-95 (TestValidTxProof), literal cases at lines 54-56.
// Lines 57-59 use makeTxs (cmtrand.Bytes), which is random per run; not copied.
// ---------------------------------------------------------------------------

var upValidTxProofCases = []struct {
	line string
	txs  types.Txs
}{
	{"54", types.Txs{{1, 4, 34, 87, 163, 1}}},
	{"55", types.Txs{{5, 56, 165, 2}, {4, 77}}},
	{"56", types.Txs{types.Tx("foo"), types.Tx("bar"), types.Tx("baz")}},
}

// tx_test.go:75: require.Error(t, proof.Validate([]byte("foobar")))
var upTxWrongDataHash = []byte("foobar")

// tx_test.go:119: for j := 0; j < 500; j++ { bad := ctest.MutateByteSlice(bin) ... }
const upTxUnchangableMutations = 500

// ---------------------------------------------------------------------------
// abci/types/types_test.go:13-45 (TestHashAndProveResults), literal at lines 14-22.
// ---------------------------------------------------------------------------

func upExecTxResults() []*abci.ExecTxResult {
	return []*abci.ExecTxResult{
		// Note, these tests rely on the first two entries being in this order.
		{Code: 0, Data: nil},
		{Code: 0, Data: []byte{}},

		{Code: 0, Data: []byte("one")},
		{Code: 14, Data: nil},
		{Code: 14, Data: []byte("foo")},
		{Code: 14, Data: []byte("bar")},
	}
}

// ---------------------------------------------------------------------------
// types/block_test.go
// ---------------------------------------------------------------------------

// block_test.go:192-206 (makeBlockID), verbatim.
func makeBlockID(hash []byte, partSetSize uint32, partSetHash []byte) types.BlockID {
	var (
		h   = make([]byte, tmhash.Size)
		psH = make([]byte, tmhash.Size)
	)
	copy(h, hash)
	copy(psH, partSetHash)
	return types.BlockID{
		Hash: h,
		PartSetHeader: types.PartSetHeader{
			Total: partSetSize,
			Hash:  psH,
		},
	}
}

// block_test.go:210-215 (emptyBytes): "This follows RFC-6962, i.e. `echo -n ” | sha256sum`."
// Asserted equal to (*Data)(nil).Hash() and new(Data).Hash() at lines 222-225.
var upEmptyBytes = []byte{
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
	0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
	0x78, 0x52, 0xb8, 0x55,
}

// block_test.go:318-333 (TestHeaderHash "Generates expected hash"), verbatim.
func upTestHeader() *types.Header {
	return &types.Header{
		Version:            cmtversion.Consensus{Block: 1, App: 2},
		ChainID:            "chainId",
		Height:             3,
		Time:               time.Date(2019, 10, 13, 16, 14, 44, 0, time.UTC),
		LastBlockID:        makeBlockID(make([]byte, tmhash.Size), 6, make([]byte, tmhash.Size)),
		LastCommitHash:     tmhash.Sum([]byte("last_commit_hash")),
		DataHash:           tmhash.Sum([]byte("data_hash")),
		ValidatorsHash:     tmhash.Sum([]byte("validators_hash")),
		NextValidatorsHash: tmhash.Sum([]byte("next_validators_hash")),
		ConsensusHash:      tmhash.Sum([]byte("consensus_hash")),
		AppHash:            tmhash.Sum([]byte("app_hash")),
		LastResultsHash:    tmhash.Sum([]byte("last_results_hash")),
		EvidenceHash:       tmhash.Sum([]byte("evidence_hash")),
		ProposerAddress:    crypto.AddressHash([]byte("proposer_address")),
	}
}

// block_test.go:333
const upTestHeaderHash = "F740121F553B5418C3EFBD343C2DBFE9E007BB67B0D020A0741374BAB65242A4"

// upHeaderByteSlices is block_test.go:359-387 verbatim (the reflection loop that
// builds the 14 Merkle leaves), with assert/require replaced by panics.
func upHeaderByteSlices(header *types.Header) [][]byte {
	byteSlices := [][]byte{}

	s := reflect.ValueOf(*header)
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)

		if f.IsZero() {
			panic("Found zero-valued field " + s.Type().Field(i).Name)
		}

		switch f := f.Interface().(type) {
		case int64, bytes.HexBytes, string:
			byteSlices = append(byteSlices, cdcEncode(f))
		case time.Time:
			bz, err := gogotypes.StdTimeMarshal(f)
			must(err)
			byteSlices = append(byteSlices, bz)
		case cmtversion.Consensus:
			bz, err := f.Marshal()
			must(err)
			byteSlices = append(byteSlices, bz)
		case types.BlockID:
			pbbi := f.ToProto()
			bz, err := pbbi.Marshal()
			must(err)
			byteSlices = append(byteSlices, bz)
		default:
			panic("unknown type")
		}
	}
	return byteSlices
}

// types/encoding_helper.go:11-47 (cdcEncode), verbatim; unexported upstream.
func cdcEncode(item any) []byte {
	if item != nil && !isTypedNil(item) && !isEmpty(item) {
		switch item := item.(type) {
		case string:
			i := gogotypes.StringValue{
				Value: item,
			}
			bz, err := i.Marshal()
			if err != nil {
				return nil
			}
			return bz
		case int64:
			i := gogotypes.Int64Value{
				Value: item,
			}
			bz, err := i.Marshal()
			if err != nil {
				return nil
			}
			return bz
		case bytes.HexBytes:
			i := gogotypes.BytesValue{
				Value: item,
			}
			bz, err := i.Marshal()
			if err != nil {
				return nil
			}
			return bz
		default:
			return nil
		}
	}

	return nil
}

// types/utils.go:10-18 (isTypedNil), verbatim.
func isTypedNil(o any) bool {
	rv := reflect.ValueOf(o)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// types/utils.go:21-29 (isEmpty), verbatim.
func isEmpty(o any) bool {
	rv := reflect.ValueOf(o)
	switch rv.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
		return rv.Len() == 0
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// types/validator_set_test.go:23-53 (TestValidatorSetBasic): NewValidatorSet(nil)
// (line 29) hashes to the literal at lines 49-53.
// ---------------------------------------------------------------------------

var upEmptyValSetHash = []byte{
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
	0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
	0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
}

// ---------------------------------------------------------------------------
// types/consensus_breakage_test.go
// ---------------------------------------------------------------------------

// consensus_breakage_test.go:19 (TestValidatorsHash): vset.Hash().
var upValidatorsHash = []byte{0x3a, 0x37, 0x2b, 0xdc, 0xb3, 0xb9, 0x41, 0x8f, 0x55, 0xe1, 0x32, 0x37, 0xc6, 0xf2, 0x80, 0x1a, 0x20, 0xf7, 0x9f, 0xbe, 0x5f, 0x46, 0xc7, 0xf3, 0xdb, 0x77, 0x80, 0x13, 0xd9, 0x3a, 0xe9, 0xd4}

// consensus_breakage_test.go:25 (TestLastCommitHash): lastCommit.Hash().
var upLastCommitHash = []byte{0x8, 0xba, 0xdc, 0xd5, 0x36, 0x3f, 0x2e, 0xb5, 0x47, 0x91, 0x0, 0xc0, 0xa, 0xea, 0x5c, 0x20, 0xb, 0x5b, 0x81, 0x2, 0x6, 0x27, 0xe9, 0x22, 0x77, 0xff, 0x82, 0xc3, 0x1, 0x1e, 0xba, 0xb5}

// consensus_breakage_test.go:37-42 (TestDataHash).
var upDataHashTxs = types.Txs{
	[]byte{0x01, 0x02, 0x03},
}

var upDataHash = []byte{0x17, 0xfd, 0x4, 0x25, 0xd0, 0x2b, 0xac, 0x41, 0x1c, 0x75, 0x83, 0xd6, 0xa9, 0xfa, 0x75, 0x80, 0x37, 0x9a, 0x26, 0x91, 0x62, 0x9e, 0x9c, 0x1c, 0xe6, 0xc6, 0x7f, 0x89, 0x53, 0x19, 0xb, 0x99}

// consensus_breakage_test.go:77 (TestEvidenceHash): evList.Hash().
var upEvidenceListHash = []byte{0x1, 0xe9, 0x26, 0x6a, 0xe5, 0x16, 0x4c, 0xba, 0xfe, 0x4a, 0x54, 0xdd, 0x55, 0x56, 0xee, 0xc, 0xa7, 0xb4, 0x3d, 0xa0, 0xec, 0xab, 0xb5, 0xc9, 0x35, 0x71, 0x3, 0xc8, 0x1f, 0xae, 0x77, 0xae}

// consensus_breakage_test.go:111-119 (deterministicValidatorSet), verbatim (t.Helper/require replaced).
func deterministicValidatorSet() *types.ValidatorSet {
	pkBytes, err := hex.DecodeString("D9838D11F68AE4679BD91BC2693CDF62FAABAEA7B4290A70ED5F200B4B67881C")
	must(err)
	pk := ed25519.PubKey(pkBytes)
	val := types.NewValidator(pk, 1)
	return types.NewValidatorSet([]*types.Validator{val})
}

// consensus_breakage_test.go:121-144 (deterministicLastCommit), verbatim.
func deterministicLastCommit() *types.Commit {
	return &types.Commit{
		Height: 1,
		Round:  0,
		BlockID: types.BlockID{
			Hash: tmhash.Sum([]byte("blockID_hash")),
			PartSetHeader: types.PartSetHeader{
				Total: 1000000,
				Hash:  tmhash.Sum([]byte("blockID_part_set_header_hash")),
			},
		},
		Signatures: []types.CommitSig{
			{
				BlockIDFlag: types.BlockIDFlagAbsent,
			},
			{
				BlockIDFlag:      types.BlockIDFlagCommit,
				ValidatorAddress: crypto.AddressHash([]byte("validator_address")),
				Timestamp:        time.Unix(1515151515, 0),
				Signature:        make([]byte, ed25519.SignatureSize),
			},
		},
	}
}

// consensus_breakage_test.go:146-167 (deterministicVote), verbatim.
func deterministicVote(t byte, valAddress crypto.Address) *types.Vote {
	stamp, err := time.Parse(types.TimeFormat, "2017-12-25T03:00:01.234Z")
	if err != nil {
		panic(err)
	}

	return &types.Vote{
		Type:      types.SignedMsgType(t),
		Height:    3,
		Round:     2,
		Timestamp: stamp,
		BlockID: types.BlockID{
			Hash: tmhash.Sum([]byte("blockID_hash")),
			PartSetHeader: types.PartSetHeader{
				Total: 1000000,
				Hash:  tmhash.Sum([]byte("blockID_part_set_header_hash")),
			},
		},
		ValidatorAddress: valAddress,
		ValidatorIndex:   56789,
	}
}

// upEvidenceList is consensus_breakage_test.go:47-76 (TestEvidenceHash) verbatim.
func upEvidenceList() types.EvidenceList {
	valSet := deterministicValidatorSet()

	// DuplicateVoteEvidence
	valAddress := valSet.Validators[0].Address
	dp, err := types.NewDuplicateVoteEvidence(
		deterministicVote(1, valAddress),
		deterministicVote(2, valAddress),
		time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		valSet,
	)
	must(err)

	// LightClientAttackEvidence
	lcE := types.LightClientAttackEvidence{
		ConflictingBlock: &types.LightBlock{
			SignedHeader: &types.SignedHeader{},
			ValidatorSet: valSet,
		},
		CommonHeight: 1,

		ByzantineValidators: valSet.Validators,
		TotalVotingPower:    100,
		Timestamp:           time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	// EvidenceList
	return types.EvidenceList{dp, &lcE}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
