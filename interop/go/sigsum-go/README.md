<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# sigsum-go interop check

This program checks truestamp_merkle against
[sigsum.org/sigsum-go](https://git.glasklar.is/sigsum/core/sigsum-go) v0.14.1.
sigsum-go implements RFC 9162 Merkle trees, and every check here uses its own
functions.

## Layout

In the truestamp_merkle repository the program is `interop/go/sigsum-go/`
(Go module `github.com/truestamp/truestamp-merkle-elixir/interop/go/sigsum-go`),
its fixture file is `vectors/interop/sigsum-go.json`, and the library's own
known answers are `vectors/merkle.json`. The library's test suite runs, from
this directory:

    go run . -fixtures /abs/path/vectors/interop/sigsum-go.json -ours /abs/path/vectors/merkle.json

and requires exit status 0. To regenerate the fixture file, from this
directory:

    go run . -fixtures ../../../vectors/interop/sigsum-go.json -write

## Flags

- `-fixtures <path>` (required) is the sigsum-go fixture file: its published
  known answers and generated cases. The program checks every entry with
  sigsum-go, re-runs the upstream test assertions, and confirms each verdict
  against an independent RFC 9162 reference. The file must also be
  byte-identical to what `-write` regenerates.
- `-write` regenerates the fixture file from the upstream literals and
  sigsum-go, then checks it. Running it twice gives the same bytes.
- `-ours <path>` also checks the library's own known answers with sigsum-go:
  - every tree root, the empty tree included;
  - every leaf's audit path, and each tree's depth (its longest path);
  - every listed path and its binary form;
  - every `walk_accepts` case;
  - every `walk_refusals` case named `index_out_of_range` or
    `wrong_path_length`. Each one must be refused for that reason, even
    against the root its path reaches with no checks. sigsum-go is strict, so
    the lax-acceptance constant is 0.

  `constants`, `trees`, `walk_accepts` and `walk_refusals` must be present and
  non-empty, and a tree with entries must list paths. Fields the program does
  not read are ignored. A field it reads that is missing, has the wrong type
  or holds a malformed value is a failure. The only skips, each counted and
  named on the OK line, are an in-scope refusal with a node that is not 64 hex
  digits (today one: the refusal whose node is `"bad"`), and an index or size
  over 2^64-1, which only happens if `constants.max_tree_size` is over 2^64-1
  too. With today's `max_tree_size` of 2^64-1 such a value is a failure.

  The `mixed-keys` tree has two keys with one digest. `merkle.Tree` refuses
  duplicate leaves, so the program builds that root with sigsum-go's hash
  functions and checks it with `merkle.VerifyInclusionTail`. Some parts of the
  vectors have no counterpart in sigsum-go and are only counted: `max_steps`,
  `entry_refusals` and `binary_refusals`.
- `-h` or `-help` prints the usage to stderr and exits 0.

## Output

On success the program prints one line per phase:

    OK fixtures sigsum.org/sigsum-go@v0.14.1: <counts>
    OK ours sigsum.org/sigsum-go@v0.14.1: <counts>

Each problem is one line starting `FAIL fixtures ` or `FAIL ours ` (after 50
of them, one more line counts the rest), and the program exits 1. A command
line error (an unknown flag, a missing or empty value, a stray argument, no
`-fixtures`) is one line, `FAIL usage: <reason>`, and exit status 1. A panic
in either phase becomes one FAIL line. The program reads only the two files
it is given, and writes only the `-fixtures` file with `-write`. Once the Go
module cache holds sigsum-go v0.14.1, it needs no network
(`GOFLAGS=-mod=mod GOPROXY=off`).

## Files

- `main.go` builds the fixture and handles the flags.
- `check.go` checks the fixture file.
- `ours.go` implements `-ours`.
- `reference.go` is the RFC 9162 reference, written with `crypto/sha256` only.
- `text.go` holds the fixture's prose.
- `upstream.go` holds the copied upstream lines, each block marked verbatim
  with its source file and line range.

The upstream material is BSD-2-Clause. `LICENSE-sigsum-go` and `NOTICE` cover
it.
