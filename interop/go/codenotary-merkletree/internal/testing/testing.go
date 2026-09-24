// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package testing stands in for the standard library's testing package inside
// upstream_tests.go, so that upstream test functions can be copied verbatim
// (header line included) and run as ordinary code. Only the parts the copied
// functions use exist here.
package testing

import "fmt"

// T collects assertion failures instead of reporting them to a test runner.
type T struct {
	Name     string
	Failures []string
}

// Errorf records one failure. The copied code reaches it only through the
// assert shim.
func (t *T) Errorf(format string, args ...interface{}) {
	t.Failures = append(t.Failures, fmt.Sprintf(format, args...))
}
