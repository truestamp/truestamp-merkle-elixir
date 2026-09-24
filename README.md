<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# truestamp_merkle

SHA-256 Merkle trees with inclusion proofs, in pure Elixir with no runtime dependencies
beyond OTP's `:crypto`.

Truestamp builds every block's tree to the contract below, and the commitments it
records on public blockchains bind those roots. The construction rules are therefore
frozen: changing one would change roots that are already on chain.

**Status:** 0.1.0, not yet published to Hex.

## Use

```elixir
entries = [%{"key" => "a", "hash" => digest_a}, %{"key" => "b", "hash" => digest_b}]
tree = Truestamp.Merkle.new(entries)
root = Truestamp.Merkle.root(tree)
steps = Truestamp.Merkle.proof(tree, "a")

{:ok, ^root} = Truestamp.Merkle.walk(digest_a, steps)
true = Truestamp.Merkle.verify(digest_a, steps, root, max_steps: 32)

binary = Truestamp.Merkle.steps_to_binary(steps)
{:ok, ^steps} = Truestamp.Merkle.steps_from_binary(binary)
```

Until it is on Hex, depend on it by commit:

```elixir
{:truestamp_merkle, github: "truestamp/truestamp-merkle-elixir", ref: "<full commit id>"}
```

The module documentation covers every function, and `SECURITY.md` what a proof does and
does not attest.

## The tree contract

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

### Proving an entry

An entry's inclusion path lists the sibling at each level of the tree, from its leaf up
to the root. Each step is `l:` or `r:` followed by the sibling's 64 lowercase hex
characters: `l` means the sibling sits to the left of the running hash, `r` to the right.

1. Start from the entry's leaf, `SHA-256(0x00 || digest)`.
2. For an `l` step the running hash becomes `SHA-256(0x01 || sibling || running)`, and
   for an `r` step `SHA-256(0x01 || running || sibling)`.
3. The hash after the last step is the root the path implies. It proves the entry only
   when it equals a root obtained some other way.

A one-entry tree's path is empty, and its root is the leaf itself. A path is refused,
never repaired. The checks run in this order, and the first that fails names the refusal:

1. `invalid_leaf`: the digest being proved is not exactly 64 lowercase hex characters.
2. `reserved_leaf`: it is the reserved digest. The padding leaf's hash may still appear
   as a sibling, and is valid there.
3. `too_many_steps`: the path has more steps than the cap. The cap is 64, a caller can
   lower it (Truestamp uses 32), and the path is refused before any step is read.
4. `invalid_step`: a step is anything but `l:` or `r:` and exactly 64 lowercase hex
   characters. Uppercase, a trailing newline and a bare hash are all refused.

A port may spell these refusals its own way, but must refuse in this order.

### Storing a path

A path has one binary form:

    byte 0         the number of steps, 0 to 64
    next bytes     ceil(steps / 8) direction bytes, least significant bit first: bit N
                   is 1 when step N is `r`, and every bit from the step count up is 0
    the rest       each sibling's 32 raw bytes, bottom to top

The empty path is the single byte `0x00`. Decoding accepts only this canonical form: a
set bit past the step count, a missing byte or a trailing one is refused, so one path
never has two encodings. For text, the form is written in unpadded base64url, and the
decoder accepts only the one spelling the encoder writes.

### Limits

- An inclusion proof holds at most 64 steps.
- A tree is at most 40 levels deep. Memory runs out long before that; construction has
  no entry limit of its own, so build trees from input you control.

## Known answers

`vectors/merkle.json` is the source of truth for this library's known answers, and a port
of the contract must reproduce every value in it. `vectors/generate.exs` writes it from
the contract above without using the library, CI fails if the file and the generator
disagree, and the tests hold the library to every value it produces. Hashes are lowercase
hex throughout. The file's sections:

- `constants`: `empty_root`, the root of a tree with no entries; `reserved_digest`;
  `padding_leaf`; and `max_steps`, the default cap on a path.
- `trees`: each tree's `entries` as listed (not sorted, so a port must sort), its `root`,
  its `depth` (levels above the leaves; 0 for an empty or one-entry tree), its
  `padded_size` (leaves after padding; 0 for an empty tree), and `rfc6962_root`, the root
  strict RFC 6962 gives the same entries, which differs from `root` exactly when padding
  was needed. Each of its `paths` gives an entry's `key` and `digest`, its `steps`, and
  their binary form as `binary_hex` and `base64url`.
- `entry_refusals`: sets of entries a tree must refuse to build from.
- `walk_accepts`: a `digest`, `steps` and `max_steps` a walk must accept, with the `root`
  it reaches.
- `walk_refusals`: the same inputs a walk must refuse, with the `error` it names.
- `binary_refusals` and `base64url_refusals`: encodings the decoders must refuse.

The values below are a summary of that file.

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

**A path.** In the two-entry tree, `key01`'s path is the single step
`r:d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f`, whose binary form
is 34 bytes, or `AQHXisvDVvoXHOQLty_6dMveBsNq78JniprxjTl1WB6Wnw` in base64url. The
vectors file has every entry's path for n = 1 to 7, and three paths in the tree below.

**A larger tree.** 300 entries with keys `lk0001` through `lk0300` and digests
`SHA-256("bigleaf<i>")` have the root
`f8c3f9a207a67fc22a297edcdf1dc0f17840ee9c8648ee3c8a7e5a71e5e42b92`, at depth 9.
`lk0001`'s path has nine steps, so its direction bits take two bytes.

## Performance

Measured with `mix run bench/performance.exs` on an Apple M3 Max with 64 GB, running
Elixir 1.20.1 on OTP 29. A tree is built by one process; the build time is the median of
three builds, and the proof and verify times are means over up to 10,000 random entries.

| Entries | Depth | Build | Build rate | Tree memory | Proof | Verify | Proof size |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 10 | 1.7 ms | 587,199/s | 273.1 KB | 2.2 us | 8.9 us | 323 B |
| 10,000 | 14 | 18.9 ms | 528,569/s | 3.0 MB | 3.0 us | 11.7 us | 451 B |
| 100,000 | 17 | 295.4 ms | 338,510/s | 28.4 MB | 4.9 us | 14.6 us | 548 B |

- **Build rate** falls as the tree grows, from over 500,000 entries a second at 10,000
  entries to about 340,000 at 100,000.
- **Proofs** hold one sibling per level, so their time and size grow with the depth, the
  base-2 logarithm of the padded entry count. Proof size is the compact binary form: a
  depth byte, the direction bits, and 32 bytes per step.
- **Verification** checks the format of every value it is given and hashes once per step,
  so it costs more than producing a proof: about 15 microseconds at 100,000 entries.
- **Tree memory** is the finished tree's heap size, counting a shared term once: about
  300 bytes per entry. Padding adds to it: 10,000 entries pad to 16,384 leaves, and every
  level above them is sized for 16,384. Building needs more than this while the input,
  the tree's levels and the finished tree are all alive; the `Truestamp.Merkle` module
  documentation gives sizing guidance for large trees.
- Timings vary between runs by a few percent, and by more on a busy machine.

Two more scripts cover the rest: `mix run bench/proof_generation_benchmark.exs` times
proof generation in bulk and compares the ways to build a tree (`new/2`, the builder, and
the stream, map and tuple wrappers), and `mix run examples/truestamp_merkle_demo.exs`
walks through the API.

## License

Apache License 2.0. See [LICENSE](./LICENSE).

Copyright (c) 2025-2026 Truestamp, Inc.
