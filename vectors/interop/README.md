<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Known answers from other implementations

Each file here holds the Merkle known answers of a Go implementation of RFC 9162 section
2.1 (the tree and inclusion proofs of RFC 6962): the roots, hashes and inclusion proofs
its tests publish, the corrupted proofs they reject, and cases computed with the
implementation's own functions from its tests' data (named `generated:`).
`production-logs.json` holds other published data instead: inclusion proofs from Rekor's
production log, the tessera and serverless-log test log, and ics23's test vectors.

`test/truestamp/merkle/interop_test.exs` checks the library against every tree root, every
inclusion verdict, every node hash, and, for every accepted proof whose tree is in the
file, the path the library itself produces. Most implementations take leaf data of any
length and the library's public API takes only 32-byte digests, so these checks work at
the leaf-hash level, through the same internal functions the public API uses; trees whose
leaf data are 32-byte digests also go through the public API. The leaf hashes of other
data are confirmed by each file's Go program, below.

| File | Implementation | Version | License | Trees | Inclusion cases | Largest tree size |
|---|---|---|---|---:|---:|---:|
| `transparency-dev-merkle.json` | github.com/transparency-dev/merkle (with Trillian and C++ CT lineage) | v0.0.2 | Apache-2.0 | 55 | 816 | 3,630,887 |
| `x-mod-sumdb-tlog.json` | golang.org/x/mod/sumdb/tlog | v0.41.0 | BSD-3-Clause | 26 | 1,215 | 100 |
| `cometbft-crypto-merkle.json` | github.com/cometbft/cometbft/crypto/merkle | v1.0.1 | Apache-2.0 | 46 | 1,430 | 100 |
| `certificate-transparency-go.json` | github.com/google/certificate-transparency-go/merkletree | v1.0.16 | Apache-2.0 | 9 | 130 | 16 |
| `codenotary-merkletree.json` | github.com/codenotary/merkletree | v0.1.2 | Apache-2.0 | 68 | 1,549 | 65 |
| `sigsum-go.json` | sigsum.org/sigsum-go | v0.14.1 | BSD-2-Clause | 108 | 1,638 | 100 |
| `production-logs.json` | Rekor proofs (via sigstore-go, sigstore-conformance, rekor, rekor-tiles), the tessera and serverless-log test log, ics23 test vectors | per source, in the file | Apache-2.0 | 18 | 420 | 1,340,288,195 |

The largest tree size is the largest in a tree or a proof; the largest trees built from
their leaves have 65,535 entries (transparency-dev). Every implementation agrees with RFC
9162 on every tree root. On inclusion verdicts, one does not: codenotary/merkletree
accepts a path cut short at the right edge, or one with extra nodes, when the chain it
computes happens to equal the root it is given. Its file keeps that verdict as `valid` and
adds `rfc9162_valid: false` for each of those 785 cases, and the library is held to the
RFC answer. ics23 carries no index or size and accepts a path of any length; the
production-logs file records that as a deviation and takes its verdicts from
transparency-dev/merkle. golang.org/x/mod's tlog loops forever in its split helper for a
tree size above 2^62; its program guards every call that takes a size from a file.

## The format

Hashes are lowercase hex. Each file has:

- `implementation`, `version`, `license`, `sources` (upstream file and line ranges), `notes`,
  `deviations` and `discrepancies`.
- `empty_root`: the root of the empty tree, or `null` if the implementation publishes none.
- `hash_checks`: `{name, kind, input_hex | left + right, hash}`, a leaf hash
  (`SHA-256(0x00 || input)`) or a node hash (`SHA-256(0x01 || left || right)`).
- `trees`: `{name, leaf_data, leaf_hashes, leaf_data_rule, tree_size, root}`. The leaves are
  listed as `leaf_hashes`, or described by `leaf_data_rule`: leaf `i`, for `i` from `first` to
  `first + tree_size - 1`, is the encoding of `i`: `u16le` (2 bytes little-endian), `u64be`
  (8 bytes big-endian) or `decimal_ascii`.
- `inclusion`: `{name, leaf_hash, leaf_index, tree_size, path, root, valid, rfc9162_valid?,
  upstream_expectation}`. `valid` is the implementation's own verdict. `rfc9162_valid`, given
  where the implementation or its upstream test disagreed with RFC 9162 or with each other,
  is RFC 9162 section 2.1.3.2's verdict, and the library is held to it. Refused cases
  include values no verifier should accept: negative indexes, a tree size of 0, and hashes
  that are not 32 bytes.

Some integers reach 2^64 - 1. A JavaScript reader needs a JSON parser that keeps 64-bit
integers exact.

## How the files are made and checked

`interop/go/<name>/` holds the Go program behind `<name>.json`. It carries the upstream
literals it copies, each marked with its module, version, file and lines, and the upstream
licenses; its `NOTICE` lists them. From that directory:

    go run . -fixtures ../../../vectors/interop/<name>.json -write   rebuild the file
    go run . -fixtures ../../../vectors/interop/<name>.json          check it
    go run . -fixtures ../../../vectors/interop/<name>.json -ours ../../../vectors/merkle.json

A check confirms every value with the implementation's own functions and fails unless the
file is exactly what `-write` produces. `-ours` also checks this library's
`vectors/merkle.json` with that implementation: every root, every path, every accepted
proof, and that the index and path-length refusals are refused (codenotary's two
acceptances among them are pinned, so a change is caught).

`mix test --include go_interop` runs all seven programs that way, and CI does so for every
push to `main` and every pull request. Plain `mix test` needs no Go: it reads the committed
files.
