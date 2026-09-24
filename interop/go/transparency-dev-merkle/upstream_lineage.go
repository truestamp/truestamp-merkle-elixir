// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains code and literals copied from github.com/google/trillian@v1.0.1
// (Apache-2.0, Copyright Google Inc.): merkle/log_verifier_test.go; and from
// github.com/google/certificate-transparency@v0.0.0-20230802103341-0fe5116f4289
// (Apache-2.0): cpp/merkletree/tree_hasher_test.cc,
// cpp/merkletree/merkle_tree_test.cc and python/ct/crypto/merkle_test.py, at
// the line ranges named below. The upstream licenses are vendored as
// LICENSE-trillian and LICENSE-certificate-transparency; see NOTICE.

package main

// Verbatim copies of fixture literals from the lineage of
// github.com/transparency-dev/merkle:
//
//   - github.com/google/trillian@v1.0.1 merkle/log_verifier_test.go
//     (the corruption logic below was used unchanged through v1.1.0; from
//     v1.1.1 to v1.4.2, the last release that still ships merkle/, the
//     inclusion fixtures and corruptions are identical to
//     transparency-dev/merkle@v0.0.2 and add nothing).
//   - github.com/google/certificate-transparency@0fe5116f4289 (master,
//     Go pseudo-version v0.0.0-20230802103341-0fe5116f4289): the C++
//     cpp/merkletree tests and the Python python/ct/crypto tests, where the
//     LeafInputs / roots / paths tables originally came from.
//
// Only values that transparency-dev/merkle@v0.0.2 does not already publish
// are used from here. Both upstream repositories are Apache-2.0.

// ---------------------------------------------------------------------------
// trillian@v1.0.1 merkle/log_verifier_test.go
// ---------------------------------------------------------------------------

// trillianReplaceWithEmptyTreeHash reproduces the "Modify single element of
// the proof" corruption of verifierCheck, merkle/log_verifier_test.go:165-173
// (trillian v1.0.1 to v1.1.0; the C++ VerifierCheck in
// cpp/merkletree/merkle_tree_test.cc:689-695 does the same). Upstream
// mutates proof[i] in place, verifies, and restores it; this collects each
// mutated proof instead of verifying it.
func trillianReplaceWithEmptyTreeHash(proof [][]byte) [][][]byte {
	var out [][][]byte
	for i := 0; i < len(proof); i++ {
		tmp := proof[i]
		proof[i] = sha256EmptyTreeHash
		out = append(out, append([][]byte(nil), proof...))
		proof[i] = tmp
	}
	return out
}

// trillianInvalidPathProbes is TestVerifyInclusionProof,
// merkle/log_verifier_test.go:302-314 (trillian v1.0.1). The signature there is
// VerifyInclusionProof(leafIndex, treeSize, proof, root, leafHash), so each
// probe has root []byte{} and leafHash []byte{1}, with an empty path. The
// "invalid root 1-4" probes at lines 316-327 (root sha256EmptyTreeHash,
// leafHash []byte{}) are identical to the second probe group of
// transparency-dev/merkle@v0.0.2 TestVerifyInclusion and are not repeated.
var trillianInvalidPathProbes = []struct {
	index, size int64
	root, leaf  []byte
	desc        string
}{
	{0, 0, []byte{}, []byte{1}, "invalid path 1"},
	{0, 1, []byte{}, []byte{1}, "invalid path 2"},
	{1, 0, []byte{}, []byte{1}, "invalid path 3"},
	{2, 1, []byte{}, []byte{1}, "invalid path 4"},
}

// ---------------------------------------------------------------------------
// certificate-transparency cpp/merkletree/tree_hasher_test.cc:28-45
// ---------------------------------------------------------------------------

// ctCppLeaves holds sha256_leaves (lines 31-39). Entries 0 and 1 ("" and "00")
// equal NodeHashes()[0][0] and [0][1] and are not repeated; entry 2 is new.
var ctCppLeaves = []struct {
	inputLength int
	input       string
	output      string
}{
	{0, "",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
	{1, "00",
		"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"},

	{16, "101112131415161718191a1b1c1d1e1f",
		"3bfb960453ebaebf33727da7a1f4db38acc051d381b6da20d6d4e88f0eabfd7a"},
}

// ctCppNodes holds sha256_nodes (lines 41-45).
var ctCppNodes = []struct {
	left, right, output string
}{
	{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"1a378704c17da31e2d05b6d121c2bb2c7d76f6ee6fa8f983e596c2d034963c57"},
}

// ---------------------------------------------------------------------------
// certificate-transparency cpp/merkletree/merkle_tree_test.cc
// ---------------------------------------------------------------------------

// ctCppWrongLeaf is the "Wrong leaf" probe of VerifierCheck, lines 677-680.
// The C++ verifier takes leaf DATA and hashes it, so the leaf hash it checks
// is HashLeaf("WrongLeaf"), a well-formed 32-byte hash. The Go tests pass
// []byte("WrongLeaf") as the leaf HASH instead, which only exercises the
// length check.
const ctCppWrongLeaf = "WrongLeaf"

// ctCppVerifyPathProbes are the "Various invalid paths" of
// TEST_F(MerkleVerifierTest, VerifyPath), lines 811-824:
// VerifyPath(leaf, tree_size, path, root, data) with an empty path and
// data = "" (so the leaf hash is HashLeaf("")). C++ leaf numbers are
// 1-based (RootFromPath rejects leaf == 0, merkle_verifier.cc:37). Only the
// probes with leaf >= 1 have a 0-based equivalent: (1, 0) -> index 0, and
// (2, 1) -> index 1. The leaf == 0 probes are not representable.
var ctCppVerifyPathProbes = []struct {
	leaf1Based, size uint64
	rootIsEmptyTree  bool
	line             int
}{
	{1, 0, false, 814},
	{2, 1, false, 815},
	{1, 0, true, 821},
	{2, 1, true, 823},
}

// ---------------------------------------------------------------------------
// certificate-transparency python/ct/crypto/merkle_test.py
// ---------------------------------------------------------------------------

// ctPyHashFullTreeLeaves is TreeHasherTest.test_hash_full_tree, lines 80-86
// (Apache-2.0):
//
//	l = iter(hasher.hash_leaf(c) for c in "abcde").next
//	h = hasher.hash_children
//	root_hash = h(h(h(l(), l()), h(l(), l())), l())
//	self.assertEqual(hasher.hash_full_tree("abcde"), root_hash)
//
// Iterating the Python 2 str "abcde" yields the five one-byte leaves a..e,
// and l() hands out their leaf hashes in that order (arguments evaluate left
// to right), so the asserted root is
// node(node(node(L(a), L(b)), node(L(c), L(d))), L(e)). ctPyHashFullTreeRoot
// transcribes that formula.
const ctPyHashFullTreeLeaves = "abcde"

func ctPyHashFullTreeRoot(h interface {
	HashLeaf([]byte) []byte
	HashChildren(l, r []byte) []byte
}) []byte {
	leaves := make([][]byte, 0, len(ctPyHashFullTreeLeaves))
	for _, c := range []byte(ctPyHashFullTreeLeaves) {
		leaves = append(leaves, h.HashLeaf([]byte{c}))
	}
	next := 0
	l := func() []byte { next++; return leaves[next-1] }
	hc := h.HashChildren
	// Go, like Python, evaluates call arguments left to right.
	root := hc(hc(hc(l(), l()), hc(l(), l())), l())
	// Guard against relying on that order: the same formula with the leaves
	// named explicitly.
	a, b, c, d, e := leaves[0], leaves[1], leaves[2], leaves[3], leaves[4]
	if explicit := hc(hc(hc(a, b), hc(c, d)), e); next != 5 || string(explicit) != string(root) {
		panic("test_hash_full_tree formula transcription")
	}
	return root
}

// ctPyOnes and ctPyZeros are MerkleVerifierTest.setUp, lines 253-254
// ("11" * 32 and "00" * 32, hex strings of 32 bytes).
const (
	ctPyOnes  = "1111111111111111111111111111111111111111111111111111111111111111"
	ctPyZeros = "0000000000000000000000000000000000000000000000000000000000000000"
)

// ctPyAllNodesLeaves is test_verify_leaf_inclusion_all_nodes_all_tree_sizes_up_to_4,
// line 466: leaves = ["aa", "bb", "cc", "dd"] (hex strings, one byte each).
var ctPyAllNodesLeaves = []string{"aa", "bb", "cc", "dd"}

// python/ct/crypto/merkle_test.py:176-198 MerkleVerifierTest.sha256_audit_path
var ctPySha256AuditPath = []string{
	"1a208aeebcd1b39fe2de247ee8db9454e1e93a312d206b87f6ca9cc6ec6f1ddd",
	"0a1b78b383f580856f433c01a5741e160d451c185910027f6cc9f828687a40c4",
	"3d1745789bc63f2da15850de1c12a5bf46ed81e1cc90f086148b1662e79aab3d",
	"9095b61e14d8990acf390905621e62b1714fb8e399fbb71de5510e0aef45affe",
	"0a332b91b8fab564e6afd1dd452449e04619b18accc0ff9aa8393cd4928451f2",
	"2336f0181d264aed6d8f3a6507ca14a8d3b3c3a23791ac263e845d208c1ee330",
	"b4ce56e300590500360c146c6452edbede25d4ed83919278749ee5dbe178e048",
	"933f6ddc848ea562e4f9c5cfb5f176941301dad0c6fdb9d1fbbe34fac1be6966",
	"b95a6222958a86f74c030be27c44f57dbe313e5e7c7f4ffb98bcbd3a03bb52f2",
	"daeeb3ce5923defd0faeb8e0c210b753b85b809445d7d3d3cd537a9aabaa9c45",
	"7fadd0a13e9138a2aa6c3fdec4e2275af233b94812784f66bcca9aa8e989f2bc",
	"1864e6ba3e32878610546539734fb5eeae2529991f130c575c73a7e25a2a7c56",
	"12842d1202b1dc6828a17ab253c02e7ce9409b5192430feba44189f39cc02d66",
	"29af64b16fa3053c13d02ac63aa75b23aa468506e44c3a2315edc85d2dc22b11",
	"b527b99934a0bd9edd154e449b0502e2c499bba783f3bc3dfe23364b6b532009",
	"4584db8ae8e351ace08e01f306378a92bfd43611714814f3d834a2842d69faa8",
	"86a9a41573b0d6e4292f01e93243d6cc65b30f06606fc6fa57390e7e90ed580f",
	"a88b98fbe84d4c6aae8db9d1605dfac059d9f03fe0fcb0d5dff1295dacba09e6",
	"06326dc617a6d1f7021dc536026dbfd5fffc6f7c5531d48ef6ccd1ed1569f2a1",
	"f41fe8fdc3a2e4e8345e30216e7ebecffee26ff266eeced208a6c2a3cf08f960",
	"40cf5bde8abb76983f3e98ba97aa36240402975674e120f234b3448911090f8d",
	"b3222dc8658538079883d980d7fdc2bef9285344ea34338968f736b04aeb387a",
}

// python/ct/crypto/merkle_test.py:200-240 MerkleVerifierTest.raw_hex_leaf
var ctPyRawHexLeaf = "" +
	"00000000013de9d2b29b000000055b308205573082043fa00302010202072b777b56df" +
	"7bc5300d06092a864886f70d01010505003081ca310b30090603550406130255533110" +
	"300e060355040813074172697a6f6e61311330110603550407130a53636f7474736461" +
	"6c65311a3018060355040a1311476f44616464792e636f6d2c20496e632e3133303106" +
	"0355040b132a687474703a2f2f6365727469666963617465732e676f64616464792e63" +
	"6f6d2f7265706f7369746f72793130302e06035504031327476f204461646479205365" +
	"637572652043657274696669636174696f6e20417574686f726974793111300f060355" +
	"040513083037393639323837301e170d3133303131343038353035305a170d31353031" +
	"31343038353035305a305331163014060355040a130d7777772e69646e65742e6e6574" +
	"3121301f060355040b1318446f6d61696e20436f6e74726f6c2056616c696461746564" +
	"311630140603550403130d7777772e69646e65742e6e657430820122300d06092a8648" +
	"86f70d01010105000382010f003082010a0282010100d4e4a4b1bbc981c9b8166f0737" +
	"c113000aa5370b21ad86a831a379de929db258f056ba0681c50211552b249a02ec00c5" +
	"37e014805a5b5f4d09c84fdcdfc49310f4a9f9004245d119ce5461bc5c42fd99694b88" +
	"388e035e333ac77a24762d2a97ea15622459cc4adcd37474a11c7cff6239f810120f85" +
	"e014d2066a3592be604b310055e84a74c91c6f401cb7f78bdb45636fb0b1516b04c5ee" +
	"7b3fa1507865ff885d2ace21cbb28fdaa464efaa1d5faab1c65e4c46d2139175448f54" +
	"b5da5aea956719de836ac69cd3a74ca049557cee96f5e09e07ba7e7b4ebf9bf167f4c3" +
	"bf8039a4cab4bec068c899e997bca58672bd7686b5c85ea24841e48c46f76830390203" +
	"010001a38201b6308201b2300f0603551d130101ff04053003010100301d0603551d25" +
	"0416301406082b0601050507030106082b06010505070302300e0603551d0f0101ff04" +
	"04030205a030330603551d1f042c302a3028a026a0248622687474703a2f2f63726c2e" +
	"676f64616464792e636f6d2f676473312d38332e63726c30530603551d20044c304a30" +
	"48060b6086480186fd6d010717013039303706082b06010505070201162b687474703a" +
	"2f2f6365727469666963617465732e676f64616464792e636f6d2f7265706f7369746f" +
	"72792f30818006082b0601050507010104743072302406082b06010505073001861868" +
	"7474703a2f2f6f6373702e676f64616464792e636f6d2f304a06082b06010505073002" +
	"863e687474703a2f2f6365727469666963617465732e676f64616464792e636f6d2f72" +
	"65706f7369746f72792f67645f696e7465726d6564696174652e637274301f0603551d" +
	"23041830168014fdac6132936c45d6e2ee855f9abae7769968cce730230603551d1104" +
	"1c301a820d7777772e69646e65742e6e6574820969646e65742e6e6574301d0603551d" +
	"0e041604144d3ae8a87ddcf046764021b87e7d8d39ddd18ea0300d06092a864886f70d" +
	"01010505000382010100ad651b199f340f043732a71178c0af48e22877b9e5d99a70f5" +
	"d78537c31d6516e19669aa6bfdb8b2cc7a145ba7d77b35101f9519e03b58e692732314" +
	"1383c3ab45dc219bd5a584a2b6333b6e1bbef5f76e89b3c187ef1d3b853b4910e895a4" +
	"57dbe7627e759f56c8484c30b22a74fb00f7b1d7c41533a1fd176cd2a2b06076acd7ca" +
	"ddc6ca6d0c2a815f9eb3ef0d03d27e7eebd7824c78fdb51679c03278cfbb2d85ae65a4" +
	"7485cb733fc1c7407834f7471ababd68f140983817c6f388b2f2e2bfe9e26608f9924f" +
	"16473462d136427d1f2801e4b870b078c20ec4ba21e22ab32a00b76522d523825bcabb" +
	"8c7b6142d624be8d2af69ecc36fb5689572a0f59c00000"

// python/ct/crypto/merkle_test.py:242-247 leaf_hash, leaf_index, tree_size, expected_root_hash
var ctPyLeafHash = "7a395c866d5ecdb0cccb623e011dbc392cd348d1d1d72776174e127a24b09c78"
var ctPyLeafIndex uint64 = 848049
var ctPyTreeSize uint64 = 3630887
var ctPyExpectedRootHash = "78316a05c9bcf14a3a4548f5b854a9adfcd46a4c034401b3ce7eb7ac2f1d0ecb"
