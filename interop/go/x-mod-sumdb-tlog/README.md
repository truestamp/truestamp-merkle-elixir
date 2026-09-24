<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# x-mod-sumdb-tlog

A Go program that checks truestamp_merkle against `golang.org/x/mod/sumdb/tlog`
v0.41.0, the transparency log behind the Go checksum database. tlog follows
RFC 9162 section 2.1 exactly, the same contract as the library.

The program lives at `interop/go/x-mod-sumdb-tlog/` in the truestamp_merkle
repository, and its fixture at `vectors/interop/x-mod-sumdb-tlog.json`.

It does two things:

1. **Fixture.** It regenerates `vectors/interop/x-mod-sumdb-tlog.json` from the
   upstream test literals with tlog's own functions, requires the file to be
   byte-identical, and checks every entry with tlog. The client_test.go cases
   take their `upstream_expectation` from a replay of the sumdb client's
   lookups through `tlog.TileHashReader`, because upstream asserts those proofs
   through the client and never through `tlog.CheckRecord`.
2. **Ours** (`-ours`). It checks the library's `vectors/merkle.json` with tlog:
   the empty root, every tree root and depth, every listed path, every
   `walk_accepts` case, and the `walk_refusals` cases for `index_out_of_range`
   and `wrong_path_length`, which tlog must refuse (tlog accepts none of them,
   and that count of 0 is pinned).

## Running

From this directory:

```sh
go run . -fixtures ../../../vectors/interop/x-mod-sumdb-tlog.json -ours ../../../vectors/merkle.json
go run . -fixtures ../../../vectors/interop/x-mod-sumdb-tlog.json -write   # regenerate, then check
```

The library's `go_interop` test tag (`mix test --include go_interop`) runs the
first command with absolute paths and requires exit status 0.

`-fixtures` is required; `-ours` and `-write` are optional. On success the
program prints `OK fixtures golang.org/x/mod@v0.41.0: <counts>`, plus
`OK ours golang.org/x/mod@v0.41.0: <counts>` with `-ours`, and exits 0. Each
problem is one line starting `FAIL fixtures ` or `FAIL ours `, and the exit
status is 1. A bad command line (an unknown flag, a flag with a missing or
empty value, a repeated flag, a positional argument, or no `-fixtures`) prints
one line `FAIL usage: <reason>` and exits 1. `-h` prints the usage to stderr
and exits 0. The program reads only the two paths it is given. After the
module cache is warm it needs no network
(`GOFLAGS=-mod=mod GOPROXY=off GOTOOLCHAIN=local go run . ...` works).

## What -ours requires

`constants`, `trees`, `walk_accepts` and `walk_refusals` must each be present
and non-empty, and every tree with entries must list paths. Members the
program does not read are ignored, so a new member does not break it. A member
it reads that is missing or has the wrong type is a failure, never a skip.
Only two things are skipped, and each is counted and named on the OK line:

- a `walk_refusals` digest or path node that is not hex, which has no byte
  value to hand tlog (today: "the path length is checked before any node",
  whose node is `"bad"`);
- an integer tlog cannot take (today: the `walk_accepts` case "64 steps under
  the default cap", whose `tree_size` of 2^64 - 1 does not fit `int64`).

Both skip counts are pinned at 1, so a new skip fails until it is looked at.

## Limits of tlog

tlog uses `int64` sizes, so a `tree_size` of 2^64 - 1 is skipped. It also never
returns for a tree of more than 2^62 leaves: its `maxpow2` helper overflows
there. The program does not pass tlog such a size from a file; it skips the
case instead.

## Files

- `main.go`: command line, fixture generation and entry-by-entry checks.
- `upstream.go`: the upstream literals, each with its file and line.
- `clientpath.go`: the sumdb client lookup replay.
- `edges.go`, `reference.go`: edge cases and an independent RFC 9162 reference.
- `sources.go`: the fixture's sources and notes.
- `ours.go`: the `-ours` check.
- `LICENSE-golang-x-mod`, `NOTICE`: upstream license and attribution.
