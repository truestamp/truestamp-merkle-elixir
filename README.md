# truestamp_merkle

SHA-256 Merkle trees with inclusion proofs, in pure Elixir with no runtime dependencies
beyond OTP's `:crypto`.

Truestamp builds every block's tree to the contract below, and the commitments it
records on public blockchains bind those roots. The construction rules are therefore
frozen: changing one would change roots that are already on chain.

**Status:** 0.1.0, not yet published to Hex. This README is a draft of the contract. It
is complete for how a tree is built; the proof encoding is added when the path walker
lands.

## The tree contract (draft)

### Inputs

An entry is a key and a digest.

- **Digest.** Exactly 64 lowercase hex characters, the spelling of a 32-byte value the
  caller has already computed. Uppercase and any other length are refused. The tree
  hashes digests, never documents.
- **Key.** A non-empty binary of at most 36 characters, drawn only from ASCII letters,
  digits, `.`, `_` and `-`. It must not begin with `__pad__` under a case-insensitive
  comparison, since that prefix is reserved for padding slots. Each key appears once,
  compared byte for byte, so `Key` and `key` are two keys. A key only orders the leaves;
  it is never hashed. Two keys may carry the same digest.
- **Reserved digest.** `96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7`,
  which is `SHA-256(0x00 0x00)`, fills the padding slots. It is refused as an entry's
  digest, and refused as the value a proof is presented for, because such a proof would
  prove a padding slot rather than an entry.

### Building a tree

1. Sort the entries by key, ascending by raw byte value. The comparison is never
   locale-aware.
2. Hash each entry to a leaf: `SHA-256(0x00 || digest)`, over the digest's 32 raw bytes.
3. Append copies of the padding leaf after the last sorted leaf until the list's length
   is a power of two. The padding leaf is `SHA-256(0x00 || reserved digest)`:
   `d37300dc2c6e038a83ee197ca0e181a77f6875afd9f537d31ca4995876481319`.
4. Hash each adjacent pair, left to right, into a node: `SHA-256(0x01 || left || right)`.
   Repeat on the resulting level until one hash remains. That hash is the root.

Two cases fall out of these rules. An empty tree's root is `SHA-256("")`, which is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. A one-entry tree has
no padding and no nodes, so its root is its only leaf and its inclusion proof is empty.

Leaf and node hashing follow RFC 6962. The padded shape does not: RFC 6962 splits any
count at the largest power of two smaller than it and adds no padding. A verifier
written strictly to RFC 6962 reproduces a root from this library only when the entry
count is 0 or a power of two.

### Limits

- An inclusion proof holds at most 64 steps.
- A tree is at most 40 levels deep. Memory runs out long before that; construction has
  no entry limit of its own, so build trees from input you control.

## Known answers

A port of the contract must reproduce these exactly.

**Small trees.** `n` entries with keys `key01` through `keyNN` and digests
`SHA-256("leaf<i>")` for `i` from 1 to `n`. Counts 3, 5, 6 and 7 are padded.

| n | Root |
|---|---|
| 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 1 | `e6f3e0324c47532b4584166b9cdcbfb5f1dceaac9b097512d0e9e8501977daa0` |
| 2 | `5d3d9c89b11a0055ba0e43c2aaf4d3814717c01a8079bc1d05db80c41852b0f5` |
| 3 | `738707d8051d65bb5b11d36cac93f7e5dccdee4676e836800a5d4e5c444103f1` |
| 4 | `1d8219ac8846f635dab3201c241583de32a73ca2f1b361cec04a419ae7806324` |
| 5 | `2012533b81a14bd8c0ba9172d14ca4bd761449bf10065c5baf89bc487497e891` |
| 6 | `148337559cd25959c1c5f80dc1b0518a05ec308fbff4db47f2e133a67234f898` |
| 7 | `a08d49ae18a1ad35c5925064aa8fba66a6dfdcc24cd1ba9047d0e87493230ed4` |

**The RFC 6962 difference.** The same inputs give different roots under strict RFC 6962
whenever padding applies:

| n | This library | Strict RFC 6962 |
|---|---|---|
| 3 | `738707d8051d65bb5b11d36cac93f7e5dccdee4676e836800a5d4e5c444103f1` | `f078fbabd10cf51db1dc3552d960996e0fdae24ca5559d3aec20bf04cb65c441` |
| 5 | `2012533b81a14bd8c0ba9172d14ca4bd761449bf10065c5baf89bc487497e891` | `3d7804d812524d931d28e05e6ee06d73a1f4c8c3a4f47a4210b14af54794b6fa` |

**A larger tree.** 300 entries with keys `lk0001` through `lk0300` and digests
`SHA-256("bigleaf<i>")` have the root
`f8c3f9a207a67fc22a297edcdf1dc0f17840ee9c8648ee3c8a7e5a71e5e42b92`, at depth 9.

## License

Apache License 2.0. See [LICENSE](./LICENSE).

Copyright (c) 2025-2026 Truestamp, Inc.
