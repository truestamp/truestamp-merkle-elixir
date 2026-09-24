// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package quietfmt stands in for fmt inside upstream_tests.go. The copied
// upstream tests print progress with fmt.Println and fmt.Printf; here those
// calls do nothing, so the checking program prints only its own result lines.
package quietfmt

// Println discards its arguments.
func Println(a ...interface{}) (n int, err error) { return 0, nil }

// Printf discards its arguments.
func Printf(format string, a ...interface{}) (n int, err error) { return 0, nil }
