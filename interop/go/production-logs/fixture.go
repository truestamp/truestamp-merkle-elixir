// Copyright (c) 2025-2026 Truestamp, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// Fixture is the shared interop fixture schema (round 2: leaf_data_rule and
// rfc9162_valid are the optional additions).
type Fixture struct {
	Implementation string      `json:"implementation"`
	Version        string      `json:"version"`
	License        string      `json:"license"`
	Sources        []string    `json:"sources"`
	EmptyRoot      *string     `json:"empty_root"`
	HashChecks     []HashCheck `json:"hash_checks"`
	Trees          []Tree      `json:"trees"`
	Inclusion      []Inclusion `json:"inclusion"`
	Deviations     []string    `json:"deviations"`
	Discrepancies  []string    `json:"discrepancies"`
	Notes          string      `json:"notes"`
}

type HashCheck struct {
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	InputHex *string `json:"input_hex,omitempty"`
	Left     *string `json:"left,omitempty"`
	Right    *string `json:"right,omitempty"`
	Hash     string  `json:"hash"`
}

type LeafDataRule struct {
	Encoding string `json:"encoding"`
	First    int64  `json:"first"`
}

type Tree struct {
	Name         string        `json:"name"`
	LeafData     []string      `json:"leaf_data"`
	LeafHashes   []string      `json:"leaf_hashes"`
	LeafDataRule *LeafDataRule `json:"leaf_data_rule"`
	TreeSize     uint64        `json:"tree_size"`
	Root         string        `json:"root"`
}

type Inclusion struct {
	Name                string   `json:"name"`
	LeafHash            string   `json:"leaf_hash"`
	LeafIndex           uint64   `json:"leaf_index"`
	TreeSize            uint64   `json:"tree_size"`
	Path                []string `json:"path"`
	Root                string   `json:"root"`
	Valid               bool     `json:"valid"`
	RFC9162Valid        *bool    `json:"rfc9162_valid,omitempty"`
	UpstreamExpectation string   `json:"upstream_expectation"`
}

// parseFixture decodes a fixture file strictly: an unknown field, a value of
// the wrong type or anything after the one JSON object is an error.
func parseFixture(raw []byte) (*Fixture, error) {
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("data after the fixture object")
	}
	return &f, nil
}

// canonical renders the fixture as 2-space indented JSON with no HTML escaping
// and a trailing newline; -write produces exactly these bytes and the check
// requires the file to equal them.
func canonical(f *Fixture) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func hxs(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = hx(b)
	}
	return out
}

func sp(s string) *string { return &s }

func bp(b bool) *bool { return &b }
