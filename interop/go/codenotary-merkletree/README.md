<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# codenotary-merkletree interop check

Checks truestamp_merkle against
[github.com/codenotary/merkletree](https://github.com/codenotary/merkletree)
v0.1.2 (Apache-2.0, vChain, Inc.), an RFC 6962 / RFC 9162 section 2.1 Merkle
tree in Go.

This program lives at `interop/go/codenotary-merkletree/` in the
truestamp_merkle repository, and its fixture at
`vectors/interop/codenotary-merkletree.json`. `mix test --include go_interop`
runs, from this directory:

    go run . -fixtures <abs>/vectors/interop/codenotary-merkletree.json -ours <abs>/vectors/merkle.json

and requires exit status 0. To regenerate the fixture, run from this
directory:

    go run . -fixtures ../../../vectors/interop/codenotary-merkletree.json -write

- **Fixture check** (`-fixtures <path>`, required; one line,
  `OK fixtures github.com/codenotary/merkletree@v0.1.2: ...`). Rebuilds the
  fixture from the vendored upstream literals and from verbatim upstream
  tests run against the module, requires the file to be byte-identical, and
  re-derives every value in it with the module's functions. `-write`
  regenerates the file first.
- **`-ours <path>`** (one line, `OK ours github.com/codenotary/merkletree@v0.1.2: ...`).
  Checks the library's own vectors with the module's functions: every tree
  root (`MTH`, and `Append`/`Root` on a store, the empty tree included),
  every depth (the longest `InclusionProof` path, and `Depth` for a non-empty
  tree), every path (`MPath`, `InclusionProof`, `Path.VerifyInclusion` with
  `at = tree_size - 1`), every `walk_accepts` case, and the
  `index_out_of_range` and `wrong_path_length` `walk_refusals` cases.
  `constants`, `trees`, `walk_accepts` and `walk_refusals` must be present
  and non-empty, and a tree with entries must list paths. Unknown fields are
  ignored; a missing or mistyped field in a checked case fails. The only
  skips are a digest or path node that is not hex and an integer outside the
  module's `uint64` arguments, and the OK line counts and names each one
  (with the current vectors, one: "the path length is checked before any
  node", whose node is "bad").

Each problem prints one line: `FAIL usage: ...` for a bad command line (an
unknown flag, a missing or empty value, a repeated flag, a stray argument,
no `-fixtures`), otherwise `FAIL fixtures ...` or `FAIL ours ...`. Any FAIL
means exit status 1, and a panic in either check becomes a FAIL line.
`-h` prints the usage to stderr and exits 0.

`Path.VerifyInclusion` does not check path length: it succeeds when the
index and the last-leaf position meet after the last node and the hash
equals the root, so it accepts a valid path with nodes appended and some
right-edge prefixes. The fixture records these cases as `rfc9162_valid`
overrides. Under `-ours` the module accepts exactly two `wrong_path_length`
refusals ("one node extra", "a node for one entry"), and
`laxAcceptedWrongLength` in `ours.go` pins that number, so a change fails.

Needs Go 1.26 and github.com/codenotary/merkletree v0.1.2, which `go.sum`
pins. With a warm module cache it runs offline
(`GOFLAGS=-mod=mod GOPROXY=off GOTOOLCHAIN=local`). `NOTICE` lists the
upstream material here and its license (`LICENSE-codenotary-merkletree`).
