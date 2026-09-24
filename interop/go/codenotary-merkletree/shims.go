// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Contains material from github.com/codenotary/merkletree@v0.1.2: the
// declarations below repeat the exported names and signatures of mth.go,
// tree.go and store.go (and the Path type of tree.go) so that the copied
// upstream tests compile against them, Copyright 2019-2020 vChain, Inc.,
// licensed under the Apache License, Version 2.0
// (LICENSE-codenotary-merkletree; see NOTICE).

package main

// Package-level names used by the verbatim upstream test code in
// upstream_tests.go. Each one calls straight into
// github.com/codenotary/merkletree; none computes a hash itself. Path is a
// local copy of merkletree.Path so that its VerifyInclusion can record every
// call (arguments, result, calling upstream line) before returning the
// module's own verdict.

import (
	"crypto/sha256"

	cn "github.com/codenotary/merkletree"
)

// Storer is merkletree.Storer.
type Storer = cn.Storer

// MTH is merkletree.MTH (mth.go:26-45).
func MTH(D [][]byte) [sha256.Size]byte { return cn.MTH(D) }

// MPath is merkletree.MPath (mth.go:50-71).
func MPath(m uint64, D [][]byte) [][sha256.Size]byte { return cn.MPath(m, D) }

// NewMemStore is merkletree.NewMemStore (store.go:47-51).
func NewMemStore() Storer { return cn.NewMemStore() }

// Append is merkletree.Append (tree.go:56-59).
func Append(store Storer, b []byte) { cn.Append(store, b) }

// Root is merkletree.Root (tree.go:41-47).
func Root(store Storer) [sha256.Size]byte { return cn.Root(store) }

// Depth is merkletree.Depth (tree.go:32-38).
func Depth(store Storer) int { return cn.Depth(store) }

// LeafHash is merkletree.LeafHash (tree.go:50-52).
func LeafHash(b []byte) [sha256.Size]byte { return cn.LeafHash(b) }

// Path mirrors merkletree.Path (tree.go:102).
type Path [][sha256.Size]byte

// InclusionProof is merkletree.InclusionProof (tree.go:154-186).
func InclusionProof(store Storer, at, i uint64) (p Path) {
	return Path(cn.InclusionProof(store, at, i))
}

// VerifyInclusion returns merkletree.Path.VerifyInclusion (tree.go:192-215)
// and records the call.
func (p Path) VerifyInclusion(at, i uint64, root, leaf [sha256.Size]byte) bool {
	ok := cn.Path(p).VerifyInclusion(at, i, root, leaf)
	file, line := callerUpstream(1)
	c := &verifyCall{
		file: file, line: line, fn: currentUpstreamTest,
		at: at, i: i, root: root, leaf: leaf,
		path: append([][sha256.Size]byte{}, p...), result: ok,
	}
	recorded = append(recorded, c)
	lastCall = c
	return ok
}

// verifyCall is one recorded Path.VerifyInclusion call from upstream code.
type verifyCall struct {
	file     string // upstream file of the calling line
	line     int    // upstream line of the call
	fn       string // upstream test function running
	at, i    uint64
	root     [sha256.Size]byte
	leaf     [sha256.Size]byte
	path     [][sha256.Size]byte
	result   bool  // the module's verdict
	asserted *bool // upstream's asserted verdict, when an assertion followed
	assertOK bool  // the assertion held
}

var (
	recorded            []*verifyCall
	lastCall            *verifyCall
	currentUpstreamTest string
)
