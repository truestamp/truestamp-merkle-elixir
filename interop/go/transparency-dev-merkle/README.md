<!--
Copyright (c) 2025-2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# transparency-dev/merkle interop check

A Go program that checks truestamp_merkle's interop fixture for
[github.com/transparency-dev/merkle](https://github.com/transparency-dev/merkle)
v0.0.2 with that implementation's own functions. It can also check the
library's own known answers (`vectors/merkle.json`) the same way.

The program is `interop/go/transparency-dev-merkle/` and its fixture is
`vectors/interop/transparency-dev-merkle.json`. From the program directory:

```sh
go run . -fixtures ../../../vectors/interop/transparency-dev-merkle.json
go run . -fixtures ../../../vectors/interop/transparency-dev-merkle.json -ours ../../../vectors/merkle.json
go run . -fixtures ../../../vectors/interop/transparency-dev-merkle.json -write
```

The last command regenerates the fixture from the upstream literals and then
checks it. `-fixtures` is required. `-ours` is optional, but when it is
given its path must not be empty.

On success the program prints one line per phase and exits 0:
`OK fixtures github.com/transparency-dev/merkle@v0.0.2: ...` and, with
`-ours`, `OK ours github.com/transparency-dev/merkle@v0.0.2: ...`. Each
problem prints one line starting `FAIL fixtures ` or `FAIL ours `, and the
exit status is 1. A usage error (an unknown flag, a missing or empty value, a
positional argument) prints the single line `FAIL usage: <reason>` and exits
1. `-h` prints the usage to stderr and exits 0.

The fixture check confirms every hash, tree root and inclusion verdict with
the implementation. It reruns the upstream assertions over the verbatim
upstream literals, and it requires the file to be exactly what `-write`
produces. It also reproduces the two subtree-vector digests published on
upstream main.

The `-ours` check requires the sections `constants`, `trees`, `walk_accepts`
and `walk_refusals` to be present and non-empty, and every tree with entries
to list paths. A member the check uses that is missing or has the wrong JSON
type is a failure; members it does not use are ignored. It covers the empty
root, `max_tree_size` and `max_steps`, and every tree's root and depth (the
longest audit path from the implementation's prover). It confirms that every
listed path verifies and equals the implementation's own proof, and that every
`walk_accepts` case verifies. Every `walk_refusals` case named
`index_out_of_range` or `wrong_path_length` must be refused for that reason.
The implementation is strict, so the pinned lax-accept count is 0. The one
case with the non-hex path node `"bad"` has no byte value to pass and is
skipped; that skip count is pinned at 1 and the case is named on the OK line.

Apart from the two files it is given, the program reads nothing at run time.
The upstream main-branch testdata is embedded from `testdata/`. Once the
module cache is warm, it needs no network
(`GOFLAGS=-mod=mod GOPROXY=off GOTOOLCHAIN=local`).

Upstream material and licenses are listed in `NOTICE`, with the license
texts in `LICENSE-*`.
