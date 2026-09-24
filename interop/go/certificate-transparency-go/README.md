<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# certificate-transparency-go interop check

This Go program checks Merkle known answers against
`github.com/google/certificate-transparency-go` v1.0.16. That is the last
release with its own RFC 6962 Merkle code, in package `merkletree`. The
program lives at `interop/go/certificate-transparency-go/` in the
truestamp_merkle library, and its fixture at
`vectors/interop/certificate-transparency-go.json`.

It does two things:

1. It checks the fixture of that module's published known answers. It
   regenerates the fixture from upstream test code (held byte for byte in
   `upstream_vectors.go`) and from the module's own hasher and verifier. The
   file must equal that output byte for byte, and every value is checked again.
2. With `-ours`, it checks truestamp_merkle's own vectors
   (`vectors/merkle.json`) with the module's `TreeHasher` and
   `MerkleVerifier`. The module has no tree builder and no prover, so roots
   come from an RFC 9162 recursion that hashes only through the module's
   hasher, the module's verifier must accept every leaf and path, and each
   tree's `depth` must be its longest RFC 9162 path over the module's hasher.
   The `index_out_of_range` and `wrong_path_length` refusals must be refused
   for the same reason.

## Running it

From this directory:

    go run . -fixtures ../../../vectors/interop/certificate-transparency-go.json
    go run . -fixtures ../../../vectors/interop/certificate-transparency-go.json -write
    go run . -fixtures ../../../vectors/interop/certificate-transparency-go.json -ours ../../../vectors/merkle.json

The first checks the fixture, the second regenerates it and then checks it,
and the third also checks the library's own vectors. The library's opt-in
`go_interop` tests run the third form with absolute paths and require exit
status 0.

`-fixtures` is required. On success the program prints
`OK fixtures github.com/google/certificate-transparency-go@v1.0.16: <counts>`
and, with `-ours`, `OK ours github.com/google/certificate-transparency-go@v1.0.16: <counts>`,
then exits 0. Each problem prints one line starting `FAIL fixtures ` or
`FAIL ours `, and the program exits 1. A bad command line (an unknown flag, a
missing or empty value, a stray argument) prints the single line
`FAIL usage: <reason>` and exits 1. `-h` prints the usage to stderr and exits 0.

## How strict `-ours` is

`constants`, `trees`, `walk_accepts` and `walk_refusals` must be present and
non-empty, and every tree with entries must list paths. Unknown fields are
ignored, so a new field does not break the check. In a case the program
checks, a required field that is missing or has the wrong type is a FAIL.
Two kinds of case are skipped, counted and named on the OK line: a checked
refusal whose digest or path node is not a hex digest, so there is no byte
value to pass to the module, and an integer that does not fit an `int64`. The
expected counts are pinned in `ours.go`: 0 refusals accepted, 1 `walk_accepts`
case skipped (`tree_size` 2^64 - 1) and 1 in-scope `walk_refusals` case
skipped (the path node `"bad"`). Any other count is a FAIL.

The program reads nothing outside this directory apart from the two paths it
is given. It needs Go 1.26 and the modules in `go.sum`. Once they are in the
module cache it needs no network (`GOFLAGS=-mod=mod GOPROXY=off` works).

## Files

- `main.go`: the fixture check, and the command line.
- `ours.go`: the `-ours` check.
- `upstream_vectors.go`: upstream test code, copied byte for byte.
- `testdata/certificate-transparency-go@v1.0.16/`: upstream files vendored
  byte for byte. Their SHA-256 values are pinned in `main.go`.
- `LICENSE-certificate-transparency-go`, `NOTICE`: upstream license and
  attribution.
