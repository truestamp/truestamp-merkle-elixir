// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

type checker struct {
	errs                           []string
	hashChecks, trees, treeLeaves  int
	treeProofs                     int
	inclusion, valid, invalid      int
	published, generated           int
	upstreamValid, upstreamInvalid int
	overrides                      int
}

func (c *checker) fail(format string, args ...any) {
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
}

var (
	hash64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexAny = regexp.MustCompile(`^([0-9a-f]{2})*$`)
)

func (c *checker) h32(where, s string) []byte {
	if !hash64.MatchString(s) {
		c.fail("%s: %q is not 64 lowercase hex characters", where, s)
		return nil
	}
	b, _ := hex.DecodeString(s)
	return b
}

func (c *checker) data(where, s string) []byte {
	if !hexAny.MatchString(s) {
		c.fail("%s: input is not lowercase hex", where)
		return nil
	}
	b, _ := hex.DecodeString(s)
	return b
}

// checkFixture re-derives every value in the file with transparency-dev/merkle
// v0.0.2 and with the RFC 9162 reference.
func (c *checker) checkFixture(f *Fixture) {
	h := rfc6962.DefaultHasher
	if strings.TrimSpace(f.Implementation) == "" || f.Version == "" || f.License == "" || len(f.Sources) == 0 || f.Notes == "" {
		c.fail("header fields must be non-empty")
	}
	if len(f.HashChecks) == 0 || len(f.Trees) == 0 || len(f.Inclusion) == 0 {
		c.fail("hash_checks, trees and inclusion must all be non-empty")
	}
	if f.EmptyRoot == nil {
		c.fail("empty_root is null")
	} else if r := c.h32("empty_root", *f.EmptyRoot); r != nil {
		if !bytes.Equal(r, h.EmptyRoot()) || !bytes.Equal(r, refEmpty()) {
			c.fail("empty_root %s is not SHA-256 of the empty string", *f.EmptyRoot)
		}
	}
	names := map[string]bool{}
	seen := func(kind, name string) {
		if name == "" || names[kind+name] {
			c.fail("%s name %q is empty or repeated", kind, name)
		}
		names[kind+name] = true
	}

	for _, hc := range f.HashChecks {
		c.hashChecks++
		seen("hash_check", hc.Name)
		want := c.h32(hc.Name, hc.Hash)
		switch hc.Kind {
		case "leaf":
			if hc.InputHex == nil || hc.Left != nil || hc.Right != nil {
				c.fail("%s: a leaf check needs input_hex only", hc.Name)
				continue
			}
			in := c.data(hc.Name, *hc.InputHex)
			if !bytes.Equal(h.HashLeaf(in), want) || !bytes.Equal(refLeaf(in), want) {
				c.fail("%s: leaf hash mismatch", hc.Name)
			}
		case "node":
			if hc.InputHex != nil || hc.Left == nil || hc.Right == nil {
				c.fail("%s: a node check needs left and right only", hc.Name)
				continue
			}
			l, r := c.h32(hc.Name, *hc.Left), c.h32(hc.Name, *hc.Right)
			if !bytes.Equal(h.HashChildren(l, r), want) || !bytes.Equal(refNode(l, r), want) {
				c.fail("%s: node hash mismatch", hc.Name)
			}
		default:
			c.fail("%s: unknown kind %q", hc.Name, hc.Kind)
		}
	}

	for _, t := range f.Trees {
		c.trees++
		seen("tree", t.Name)
		if t.LeafDataRule != nil {
			c.fail("%s: this fixture uses no leaf_data_rule", t.Name)
			continue
		}
		var lh [][]byte
		switch {
		case t.LeafHashes != nil:
			for _, s := range t.LeafHashes {
				lh = append(lh, c.h32(t.Name, s))
			}
		case t.LeafData != nil:
			for _, s := range t.LeafData {
				lh = append(lh, h.HashLeaf(c.data(t.Name, s)))
			}
		default:
			c.fail("%s: no leaves", t.Name)
			continue
		}
		if t.LeafData != nil {
			if len(t.LeafData) != len(lh) {
				c.fail("%s: leaf_data and leaf_hashes differ in length", t.Name)
				continue
			}
			for i, s := range t.LeafData {
				d := c.data(t.Name, s)
				if !bytes.Equal(h.HashLeaf(d), lh[i]) || !bytes.Equal(refLeaf(d), lh[i]) {
					c.fail("%s: leaf %d data does not hash to its leaf hash", t.Name, i)
				}
			}
		}
		if uint64(len(lh)) != t.TreeSize {
			c.fail("%s: %d leaves for tree_size %d", t.Name, len(lh), t.TreeSize)
			continue
		}
		c.treeLeaves += len(lh)
		root := c.h32(t.Name, t.Root)
		if !bytes.Equal(tdmRoot(lh), root) || !bytes.Equal(refMTH(lh), root) {
			c.fail("%s: root mismatch", t.Name)
			continue
		}
		// every leaf of every tree must prove against the root with transparency-dev/merkle
		for m := range lh {
			p := refPath(uint64(m), lh)
			if err := proof.VerifyInclusion(h, uint64(m), t.TreeSize, lh[m], p, root); err != nil {
				c.fail("%s: leaf %d does not prove against the root: %v", t.Name, m, err)
			}
			c.treeProofs++
		}
	}

	for _, inc := range f.Inclusion {
		c.inclusion++
		seen("inclusion", inc.Name)
		leaf, root := c.h32(inc.Name, inc.LeafHash), c.h32(inc.Name, inc.Root)
		path := [][]byte{}
		for _, p := range inc.Path {
			path = append(path, c.h32(inc.Name, p))
		}
		tdm := proof.VerifyInclusion(h, inc.LeafIndex, inc.TreeSize, leaf, path, root) == nil
		rfc := refVerify(leaf, inc.LeafIndex, inc.TreeSize, path, root)
		if tdm != inc.Valid {
			c.fail("%s: valid=%v but transparency-dev/merkle says %v", inc.Name, inc.Valid, tdm)
		}
		if inc.RFC9162Valid != nil {
			c.overrides++
			if *inc.RFC9162Valid == inc.Valid {
				c.fail("%s: rfc9162_valid is set but equals valid", inc.Name)
			}
			if *inc.RFC9162Valid != rfc {
				c.fail("%s: rfc9162_valid=%v but the RFC reference says %v", inc.Name, *inc.RFC9162Valid, rfc)
			}
		} else if rfc != inc.Valid {
			c.fail("%s: RFC 9162 says %v, valid=%v, and rfc9162_valid is missing", inc.Name, rfc, inc.Valid)
		}
		switch inc.UpstreamExpectation {
		case "valid":
			c.upstreamValid++
		case "invalid":
			c.upstreamInvalid++
		case "none":
		default:
			c.fail("%s: upstream_expectation %q", inc.Name, inc.UpstreamExpectation)
		}
		if inc.Valid {
			c.valid++
		} else {
			c.invalid++
		}
		if strings.HasPrefix(inc.Name, genPrefix) {
			c.generated++
			if inc.UpstreamExpectation != "none" {
				c.fail("%s: a generated case cannot carry an upstream expectation", inc.Name)
			}
		} else {
			c.published++
		}
	}
}
