<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# production-logs interop check

This Go program lives at `interop/go/production-logs/` and checks
`vectors/interop/production-logs.json`: Merkle inclusion proofs and roots
published by production transparency logs and their test suites (sigstore-go,
rekor, rekor-tiles, sigstore-conformance, tessera, serverless-log and ics23).
It re-derives every value with transparency-dev/merkle v0.0.2 and an RFC 9162
reference written from the RFC, and requires the file to equal the bytes it
regenerates from the vendored upstream data.

Run it from this directory. `-fixtures` is required.

```sh
go run . -fixtures ../../../vectors/interop/production-logs.json          # check
go run . -fixtures ../../../vectors/interop/production-logs.json -write   # regenerate, then check
go run . -fixtures ../../../vectors/interop/production-logs.json -ours ../../../vectors/merkle.json   # also check the library's own vectors
```

On success it prints one `OK fixtures production-logs@<version>: ...` line
and, with `-ours`, one `OK ours production-logs@<version>: ...` line, where
`<version>` is the fixture's version string with its spaces replaced by `+`.
Each problem is one line starting `FAIL fixtures ` or `FAIL ours `, and a bad
flag, a missing or empty path or a positional argument is one
`FAIL usage: ...` line; any of these exits 1. `-h` prints usage to stderr and
exits 0.

`-ours` requires the sections `constants`, `trees`, `walk_accepts` and
`walk_refusals` to be present and non-empty, and every tree with entries to
publish paths. It checks each tree's root, `depth` (the longest proof from
transparency-dev/merkle's prover) and paths, every `walk_accepts` case, and the
in-scope `walk_refusals` cases (`index_out_of_range` and `wrong_path_length`,
each refused with transparency-dev/merkle's matching error). Unknown fields are
ignored; a field it reads that is missing or has the wrong JSON type is a
failure. The only skips, counted and named on the `OK ours` line, are an
in-scope refusal whose digest or a path node is not hex (no byte value exists)
and an integer outside transparency-dev/merkle's `uint64`.

The upstream files it reads are vendored under `testdata/` and compiled in, so
it reads nothing outside this directory except the two paths it is given, and
needs no network once the Go module cache is warm. `NOTICE` lists each upstream
source, its version and license, the files here that hold its material, and
every vendored file; the license texts are in the `LICENSE-*` files.
