// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package assert stands in for github.com/stretchr/testify/assert inside
// upstream_tests.go. It implements only the functions the copied upstream
// tests call, with the names and parameter lists those calls need and the
// pass/fail semantics testify v1.4.0 gives the values they pass (equality is
// reflect.DeepEqual for these types; Nil accepts a nil interface or a nil
// chan, func, interface, map, pointer or slice). No testify code is copied:
// the bodies and failure messages here are original.
//
// Every boolean assertion is reported to OnBool, which the checking program
// uses to attach upstream's asserted verdict to the VerifyInclusion call that
// produced the value.
package assert

import (
	"fmt"
	"reflect"
)

// TestingT is the subset of *testing.T the assertions need.
type TestingT interface {
	Errorf(format string, args ...interface{})
}

// OnBool is called by True (expected true) and False (expected false).
var OnBool func(value, expected bool)

func fail(t TestingT, what string, msgAndArgs ...interface{}) bool {
	if len(msgAndArgs) > 0 {
		what += " " + fmt.Sprint(msgAndArgs...)
	}
	t.Errorf("%s", what)
	return false
}

// True asserts value is true.
func True(t TestingT, value bool, msgAndArgs ...interface{}) bool {
	if OnBool != nil {
		OnBool(value, true)
	}
	if !value {
		return fail(t, "assert.True: the value is false", msgAndArgs...)
	}
	return true
}

// False asserts value is false.
func False(t TestingT, value bool, msgAndArgs ...interface{}) bool {
	if OnBool != nil {
		OnBool(value, false)
	}
	if value {
		return fail(t, "assert.False: the value is true", msgAndArgs...)
	}
	return true
}

// Equal asserts reflect.DeepEqual(expected, actual).
func Equal(t TestingT, expected, actual interface{}, msgAndArgs ...interface{}) bool {
	if !reflect.DeepEqual(expected, actual) {
		return fail(t, fmt.Sprintf("assert.Equal: want %v, have %v", expected, actual), msgAndArgs...)
	}
	return true
}

// Len asserts reflect.ValueOf(object).Len() == length.
func Len(t TestingT, object interface{}, length int, msgAndArgs ...interface{}) bool {
	v := reflect.ValueOf(object)
	switch v.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
	default:
		return fail(t, fmt.Sprintf("assert.Len: a %T has no length", object), msgAndArgs...)
	}
	if v.Len() != length {
		return fail(t, fmt.Sprintf("assert.Len: want length %d, have %d", length, v.Len()), msgAndArgs...)
	}
	return true
}

// Nil asserts that object is nil.
func Nil(t TestingT, object interface{}, msgAndArgs ...interface{}) bool {
	if object == nil {
		return true
	}
	v := reflect.ValueOf(object)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		if v.IsNil() {
			return true
		}
	}
	return fail(t, fmt.Sprintf("assert.Nil: have %#v", object), msgAndArgs...)
}
