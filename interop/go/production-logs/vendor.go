// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"embed"
	"io/fs"
	"path"
	"sort"
)

// Every upstream data file the program reads is vendored under testdata/ and
// compiled in, together with the upstream LICENSE-* files, so the program reads
// nothing outside its module directory except the -fixtures and -ours paths.
// NOTICE names the origin, version and license of each file; vendorSHA256 pins
// their bytes.
//
//go:embed all:testdata LICENSE-*
var vendored embed.FS

// readVendored returns a vendored file by its path under testdata/.
func readVendored(p string) []byte {
	b, err := vendored.ReadFile(path.Join("testdata", p))
	if err != nil {
		panic(err)
	}
	return b
}

// checkVendored confirms that the embedded files are exactly the pinned upstream
// copies: same set of paths (relative to the module directory), same SHA-256.
func (b *builder) checkVendored() {
	seen := map[string]bool{}
	err := fs.WalkDir(vendored, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		seen[p] = true
		want, ok := vendorSHA256[p]
		if !ok {
			b.fail("vendored file %s is not in the pinned manifest", p)
			return nil
		}
		raw, _ := vendored.ReadFile(p)
		sum := sha256.Sum256(raw)
		b.expect(hx(sum[:]) == want, "vendored file %s has SHA-256 %s, pinned %s", p, hx(sum[:]), want)
		return nil
	})
	if err != nil {
		b.fail("walking vendored files: %v", err)
	}
	var missing []string
	for p := range vendorSHA256 {
		if !seen[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		b.fail("pinned vendored file %s is missing", m)
	}
}
