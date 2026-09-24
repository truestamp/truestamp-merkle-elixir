<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# cometbft-crypto-merkle interop check

A Go program that confirms the published Merkle known answers of
`github.com/cometbft/cometbft/crypto/merkle` v1.0.1 (an RFC 9162 section 2.1
tree) with that implementation's own functions, and checks the library's own
vectors with the same implementation.

In the truestamp_merkle repository the program is `interop/go/cometbft-crypto-merkle/`
and its fixture is `vectors/interop/cometbft-crypto-merkle.json`. From the
program directory:

```sh
go run . -fixtures ../../../vectors/interop/cometbft-crypto-merkle.json
go run . -fixtures ../../../vectors/interop/cometbft-crypto-merkle.json -ours ../../../vectors/merkle.json
go run . -fixtures ../../../vectors/interop/cometbft-crypto-merkle.json -write
```

- `-fixtures` (required): the fixture file. The program rebuilds it from the
  upstream test literals (`upstream.go`, `upstream_extra.go`, each cited by
  file and line) and the implementation, requires the file to match byte for
  byte, and re-checks every value in it against the implementation and an
  independent RFC 9162 reference (`rfc9162.go`). It prints one line
  `OK fixtures github.com/cometbft/cometbft/crypto/merkle@v1.0.1: <counts>`.
- `-ours` (optional, must name a file): also checks `vectors/merkle.json`
  (`ours.go`) and prints
  `OK ours github.com/cometbft/cometbft/crypto/merkle@v1.0.1: <counts>`. The
  sections `constants`, `trees`, `walk_accepts` and `walk_refusals` must be
  present and non-empty, and every tree with entries must list a path. It
  checks every tree root, every tree's `depth` against the longest path the
  implementation's prover produces, every listed path, every `walk_accepts`
  case, and every `walk_refusals` case whose error is `index_out_of_range` or
  `wrong_path_length` (the implementation must refuse all of them). Unknown
  fields are ignored; a field the program reads that is missing or has the
  wrong type is a failure. Two cases are skipped, counted and named on the OK
  line: the `walk_accepts` case whose `tree_size` is 2^64 - 1 (proof indices
  are `int64`), and the `walk_refusals` case "the path length is checked
  before any node", whose node `"bad"` is not hex and so has no byte value.
- `-write`: regenerates the fixture file, then checks it.

Each problem prints one line beginning `FAIL fixtures ` or `FAIL ours `, and
the exit status is 1. A bad command line (unknown flag, missing or empty value,
stray argument) prints one line `FAIL usage: <reason>` and exits with status 1;
`-h` prints the usage to stderr and exits with status 0. The program reads only
the two paths it is given. The first build needs the module proxy; after that it
runs offline (`GOFLAGS=-mod=mod GOPROXY=off`).

Upstream material and its license are listed in `NOTICE` and
`LICENSE-cometbft`.
