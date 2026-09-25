<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# truestamp_merkle

SHA-256 Merkle trees with inclusion proofs, in pure Elixir with no runtime dependencies
beyond OTP's `:crypto`.

The tree is RFC 9162's Merkle Tree Hash over entries sorted by key, and its proofs are
RFC 9162 inclusion proofs. The contract below is meant never to change: Truestamp builds the
trees behind its blocks with this library and commits those blocks' hashes to public
blockchains, so a changed rule would break proofs already given out.

**Status:** 0.1.0, not yet published to Hex.

## Use

```elixir
entries = [%{"key" => "a", "hash" => digest_a}, %{"key" => "b", "hash" => digest_b}]
tree = Truestamp.Merkle.new(entries)
root = Truestamp.Merkle.root(tree)
proof = Truestamp.Merkle.proof(tree, "a")
# %{leaf_index: 0, tree_size: 2, path: ["<64 hex characters>"]}

{:ok, ^root} = Truestamp.Merkle.walk(digest_a, proof)
true = Truestamp.Merkle.verify(digest_a, proof, root, max_steps: 32)

binary = Truestamp.Merkle.proof_to_binary(proof)
{:ok, ^proof} = Truestamp.Merkle.proof_from_binary(binary)
```

Until it is on Hex, depend on it by commit:

```elixir
{:truestamp_merkle, github: "truestamp/truestamp-merkle-elixir", ref: "<full commit id>"}
```

The module documentation covers every function, and `SECURITY.md` what a proof does and
does not attest.

## The tree contract

The tree is the Merkle Tree Hash of RFC 9162 section 2.1.1, computed over the entries'
digests in key order, and a proof is the audit path of section 2.1.3.1, verified by the
algorithm of section 2.1.3.2. RFC 6962 defines the same tree and the same audit path, so
an implementation of either RFC reproduces this library's roots and accepts its proofs
when it is given the sorted digests as its leaf data.

### Inputs

An entry is a key and a digest.

- **Digest.** Exactly 64 lowercase hex characters, the spelling of a 32-byte value the
  caller has already computed. Uppercase and any other length are refused. The tree
  hashes digests, never documents.
- **Key.** A non-empty binary of at most 36 characters, drawn only from ASCII letters,
  digits, `.`, `_` and `-`. Each key appears once, compared byte for byte, so `Key` and
  `key` are two keys. A key only orders the leaves; it is never hashed. Two keys may
  carry the same digest.

### Building a tree

1. Sort the entries by key, ascending by raw byte value. The comparison is never
   locale-aware.
2. The sorted digests' 32 raw bytes are the RFC's leaf data `D[0]` to `D[n-1]`. The root
   is `MTH(D[n])`:
   - `MTH({})` is `SHA-256("")`, which is
     `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
   - `MTH({d})` is `SHA-256(0x00 || d)`, the leaf hash.
   - For `n > 1`, with `k` the largest power of two smaller than `n`,
     `MTH(D[n])` is `SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`.

Level by level, the same tree is: hash each adjacent pair of the level, left to right,
into `SHA-256(0x01 || left || right)`, and carry an unpaired last hash up to the next
level unchanged. Nothing is padded. A one-entry tree's root is its only leaf hash.

### Proving an entry

A proof is three values:

- `leaf_index`: the entry's position among the sorted entries, from 0.
- `tree_size`: the number of entries.
- `path`: the audit path `PATH(leaf_index, D[tree_size])`, bottom to top, each node as 64
  lowercase hex characters. A one-entry tree's path is empty.

A path carries no directions. The verifier derives each node's side from the index and
the size, per section 2.1.3.2:

1. If `leaf_index` is not below `tree_size`, fail. Set `fn` to `leaf_index`, `sn` to
   `tree_size - 1`, and `r` to the leaf hash `SHA-256(0x00 || digest)`.
2. For each node `p` of the path, in order:
   - If `sn` is 0, fail.
   - If `fn` is odd or equals `sn`, set `r` to `SHA-256(0x01 || p || r)`; then, while
     `fn` is even and not 0, shift `fn` and `sn` right by one bit.
   - Otherwise set `r` to `SHA-256(0x01 || r || p)`.
   - Shift `fn` and `sn` right by one bit.
3. If `sn` is not 0, fail. Otherwise `r` is the root the proof implies. It proves the
   entry only when it equals a root obtained some other way.

The index and size fix the path's length, so a path one node short or one node long
fails.

**Take the tree size from where the root comes from.** The root does not fix the size:
many proofs still reach the same root when `tree_size` is changed. Across every proof in
trees of 1 to 300 entries, 97% still verify with `tree_size` raised by one. The index
goes with it: the last of three entries also verifies as index 1 of a two-entry tree.
Given the true size, no other index verifies, unless another entry has the same digest.
Certificate Transparency takes the size
from the signed tree head that carries the root, and a verifier here must take it from
the record that gives it the root, never from the proof alone.

A proof is refused, never repaired. The checks run in this order, and the first that
fails names the refusal:

1. `invalid_leaf`: the digest being proved is not exactly 64 lowercase hex characters.
2. `invalid_proof`: the proof is not a map with an integer `leaf_index` of at least 0, an
   integer `tree_size` from 1 to 2^64 - 1, and a list as its `path`.
3. `index_out_of_range`: `leaf_index` is not below `tree_size`.
4. `too_many_steps`: the path the index and size require is longer than the cap. The cap
   is 64, a caller can lower it (32 admits trees of up to 2^32 entries), and the path is
   not read.
5. `wrong_path_length`: the path is not a proper list of exactly that length. It is
   counted no further than one node past it.
6. `invalid_node`: a node is not exactly 64 lowercase hex characters. Uppercase and a
   trailing newline are refused.

A port may spell these refusals its own way, but must refuse in this order.

### Storing a proof

A proof has one binary form:

    8 bytes       leaf_index, unsigned, big-endian
    8 bytes       tree_size, unsigned, big-endian
    the rest      each path node's 32 raw bytes, bottom to top

Its length is exactly 16 bytes plus 32 for each node the index and size require.
Decoding refuses anything else, so one proof has one encoding: an argument that is not a
binary is `invalid_binary`, an index not below the size (a size of 0 included) is
`index_out_of_range`, and any other length is `wrong_length`. There is no text form; spell the binary in hex or base64 as a format
needs.

### Limits

- `tree_size` is at most 2^64 - 1, so a path holds at most 64 nodes.
- A tree is at most 40 levels deep. Memory runs out long before that; construction has
  no entry limit of its own, so build trees from input you control.

## Known answers

`vectors/merkle.json` is the source of truth for this library's known answers, and a port
of the contract must reproduce every value in it. `vectors/generate.exs` writes it from
RFC 9162's recursive definitions without using the library, CI fails if the file and the
generator disagree, and the tests hold the library to every value it produces. Hashes are
lowercase hex throughout. The file's sections:

- `constants`: `empty_root`, the root of a tree with no entries; `max_steps`, the default
  cap on a path; and `max_tree_size`, 2^64 - 1.
- Every case has a `name`.
- `trees`: each tree's `entries` as listed (not sorted, so a port must sort), its `root`,
  its `depth` (the longest path; 0 for an empty or one-entry tree) and its `tree_size`.
  Each of its `paths` gives an entry's `key` and `digest`, the proof's `leaf_index`,
  `tree_size` and `path`, and the proof's binary form as `binary_hex`.
- `entry_refusals`: sets of entries a tree must refuse to build from.
- `walk_accepts`: a `digest`, a `proof` object and a `max_steps` a walk must accept, with
  the `root` it reaches and the proof's binary form as `binary_hex`.
- `walk_refusals`: the same inputs a walk must refuse, with the `error` it names. A proof
  field here may hold any JSON value, since some cases test fields of the wrong type.
- `binary_refusals`: binary forms the decoder must refuse, as `binary_hex`, with the
  `error` it names.

The values below are a summary of that file.

**Small trees.** `n` entries with keys `key01` through `keyNN` and digests
`SHA-256("leaf<i>")` for `i` from 1 to `n`.

| n | Root |
|---|---|
| 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 1 | `e6f3e0324c47532b4584166b9cdcbfb5f1dceaac9b097512d0e9e8501977daa0` |
| 2 | `5d3d9c89b11a0055ba0e43c2aaf4d3814717c01a8079bc1d05db80c41852b0f5` |
| 3 | `f078fbabd10cf51db1dc3552d960996e0fdae24ca5559d3aec20bf04cb65c441` |
| 4 | `1d8219ac8846f635dab3201c241583de32a73ca2f1b361cec04a419ae7806324` |
| 5 | `3d7804d812524d931d28e05e6ee06d73a1f4c8c3a4f47a4210b14af54794b6fa` |
| 6 | `eeb8408c501ba0bd6ad670d40a2252226bff000f8551ba513bee7e5ff6675bd9` |
| 7 | `df96a3ff1e450beeb5dc7e83e77f9a9f93508f4316d20c842a529c07fd82590f` |
| 8 | `1c24772836336888fb591f49966a0e0c11a9d9a894e4ae6c478615f08f0ac30e` |

**Proofs.** In the two-entry tree, `key01`'s proof is `leaf_index` 0, `tree_size` 2 and
the single node `d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f`, and
its binary form is 48 bytes:
`00000000000000000000000000000002d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f`.
In the three-entry tree, `key03` is the unpaired leaf, so its path is the single node
over the first two entries, which is the two-entry tree's root. The vectors file has
every entry's proof for n = 1 to 8 and for an 11-entry tree listed out of byte order, with
two keys sharing a digest, and three proofs in the tree below.

**A larger tree.** 300 entries with keys `lk0001` through `lk0300` and digests
`SHA-256("bigleaf<i>")` have the root
`41c2631074f52162508f886a3e49a03d930639906fad474f18fe77afe18111b1`, at depth 9.
`lk0001`'s path has nine nodes, and `lk0300`'s five.

## Checked against other implementations

`vectors/interop/` holds known answers from six Go implementations, transparency-dev/merkle,
golang.org/x/mod's sumdb/tlog, CometBFT, certificate-transparency-go, codenotary/merkletree
and sigsum-go, and from other published data: inclusion proofs from Rekor's production log,
the tessera and serverless-log test log, and ics23's test vectors. That is 330 trees and
7,198 inclusion cases: the values each project's tests publish, the corrupted proofs they
reject, and cases computed with each implementation's own functions from its tests' data
(named `generated:` in the files). The tests hold this library to every root and verdict in
them, at the leaf-hash level, and to the RFC 9162 verdict where an implementation departs
from it. `vectors/interop/README.md` lists every source, and
`mix test --include go_interop` also runs each implementation over the files and over this
library's own vectors.

## Performance

Measured with `mix run bench/performance.exs` (in the `prod` environment) on an Apple M3 Max
with 64 GB, running Elixir 1.20.1 on OTP 29. A tree is built by one process; the build time
is the median of three builds, and the proof and verify times are means over up to 10,000
random entries.

| Entries | Depth | Build | Build rate | Tree memory | Proof | Verify | Proof size |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 10 | 1.1 ms | 898,473/s | 271.5 KB | 1.4 us | 6.3 us | 336 B |
| 10,000 | 14 | 13.8 ms | 722,178/s | 2.7 MB | 1.7 us | 9.3 us | 464 B |
| 100,000 | 17 | 246.7 ms | 405,301/s | 26.5 MB | 3.4 us | 10.3 us | 560 B |

- **Build rate** falls as the tree grows, from about 900,000 entries a second at 1,000
  entries to about 400,000 at 100,000.
- **Proofs** hold at most one node per level, so their time and size grow with the depth,
  the base-2 logarithm of the entry count rounded up. Proof size is the binary form of the
  longest proof among the sampled entries: 16 bytes for the index and size, and 32 bytes
  per node.
- **Verification** checks the format of every value it is given and hashes once per node,
  so it costs more than producing a proof: about 10 microseconds at 100,000 entries.
- **Tree memory** is the finished tree's heap size, counting a shared term once: about 280
  bytes per entry (the script's KB and MB are 1,024 and 1,048,576 bytes). Building needs
  more than this while the input, the tree's levels and the finished tree are all alive, so
  size a large workload by memory before time.
- Timings vary between runs by a few percent, and by more on a busy machine.

`mix run bench/proof_generation_benchmark.exs` times proof generation in bulk.

## Development

`.tool-versions` pins the tools: Erlang, Elixir, Go (for the interop programs) and the
[Task](https://taskfile.dev) runner. With [mise](https://mise.jdx.dev) installed,
`mise install` puts them in place, and then:

    task setup       fetch the Hex packages and the Go interop programs' modules
    task test        run the test suite; it needs no Go
    task test-go     run the suite and the Go interop programs
    task precommit   format, then every gate CI runs: strict compile, credo, vectors,
                     unused deps, and the tests with the Go interop programs
    task example     run examples/usage.exs, the API from end to end
    task bench       measure the performance table

`task` lists the rest. CI runs `task ci`, the precommit gates with formatting checked
instead of rewritten.

## License

Apache License 2.0. See [LICENSE](./LICENSE).

Copyright (c) 2025-2026 Truestamp, Inc.
