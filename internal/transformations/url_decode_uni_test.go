// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"fmt"
	"strings"
	"testing"
)

func TestURLDecodeUni(t *testing.T) {
	tests := []struct {
		input       string
		want        string
		wantChanged bool
	}{
		{input: "", want: "", wantChanged: false},
		{input: "helloworld", want: "helloworld", wantChanged: false},
		// '+' and valid percent-encodings are real changes.
		{input: "hello+world", want: "hello world", wantChanged: true},
		{input: "%20", want: " ", wantChanged: true},
		{input: "%u0041", want: "A", wantChanged: true},
		// A '%' that is present but does not decode (invalid hex, truncated or
		// trailing) must report changed=false.
		{input: "%zz", want: "%zz", wantChanged: false},
		{input: "%2", want: "%2", wantChanged: false},
		{input: "100%", want: "100%", wantChanged: false},
		{input: "%u00zz", want: "%u00zz", wantChanged: false},
		// Uppercase %U escape.
		{input: "%U0041", want: "A", wantChanged: true},
		// U+FF1F (fullwidth '?') is absent from the best-fit table, so it
		// exercises the low-byte + 0x20 fullwidth fallback.
		{input: "%uff1f", want: "?", wantChanged: true},
		// U+0000 must not trigger the fullwidth fallback (low byte must be > 0).
		{input: "%u0000", want: "\x00", wantChanged: true},
		// A codepoint outside the best-fit table and outside the fullwidth
		// range decodes to the raw low byte, unmodified.
		{input: "%u1234", want: "4", wantChanged: true},
		// Exactly one byte short of a full %uXXXX escape: treated as
		// truncated, "%u" is copied verbatim and the rest is left as-is.
		{input: "%u004", want: "%u004", wantChanged: false},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := urlDecodeUni(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if have != tt.want {
				t.Errorf("have %q, want %q", have, tt.want)
			}
			if changed != tt.wantChanged {
				t.Errorf("input %q: changed = %t, want %t (have %q)", tt.input, changed, tt.wantChanged, have)
			}
		})
	}
}

func BenchmarkInplaceUniDecode(b *testing.B) {
	longPlain := strings.Repeat("the quick brown fox jumps over the lazy dog ", 50)
	tests := []struct {
		name  string
		input string
	}{
		{"plain-long", longPlain},
		{"plus-heavy", strings.Repeat("a+b+c+d+", 200)},
		{"percent-valid", strings.Repeat("%41%42%43%44", 200)},
		{"percent-invalid", strings.Repeat("%zz%gg%1", 200)},
		{"percent-u-plain", strings.Repeat("%u0041%u0042", 200)},
		{"percent-u-bestfit", strings.Repeat("%uff0d%u00a9%u2018", 200)},
		{"mixed-query-string", strings.Repeat("field=value%20with+spaces%26more%3Ddata", 100)},
		{"trailing-percent", longPlain + "%"},
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(tt.input)))
			for i := 0; i < b.N; i++ {
				if _, _, err := urlDecodeUni(tt.input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkURLDecode(b *testing.B) {
	tests := []string{
		"",
		"helloworld",
		"hello+world",
		"%E3%83%8F%E3%83%AD%E3%83%BC%E3%83%AF%E3%83%BC%E3%83%AB%E3%83%89",
	}

	for _, mode := range []string{"normal", "unicode"} {
		f := urlDecode
		if mode == "unicode" {
			f = urlDecodeUni
		}
		for _, tc := range tests {
			tt := tc
			b.Run(fmt.Sprintf("%s/%s", mode, tt), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					if _, _, err := f(tt); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
