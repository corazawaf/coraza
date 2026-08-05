// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestCJSDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "hello world",
			want:  "hello world",
		},
		{
			input: "\\\\0",
			want:  "\\0",
		},
		{
			input: "\\",
			want:  "\\",
		},
		// \u{H...H} is the ES2015+ extended Unicode code point escape (1-6
		// hex digits in braces), used by every modern JS engine. Before
		// recognizing it, doJsDecode fell through to the generic \C branch,
		// dropping the backslash and keeping a literal "u" while copying the
		// rest through unchanged -- silently failing to decode the escape at
		// all. See https://github.com/corazawaf/coraza/issues/1653.
		{
			input: "\\u{61}\\u{6c}\\u{65}\\u{72}\\u{74}",
			want:  "alert",
		},
		{
			input: "\\u{ff01}",
			want:  "!",
		},
		{
			input: "\\u{1}",
			want:  "\x01",
		},
		{
			input: "\\u{41}",
			want:  "A",
		},
		{
			input: "\\u{",
			want:  "u{",
		},
		{
			input: "\\u{41",
			want:  "u{41",
		},
		{
			input: "\\u{zz}",
			want:  "u{zz}",
		},
		// The full-width-ASCII fold must key off the fully resolved value,
		// not a fixed 4-digit count -- a leading-zero encoding of the same
		// value (5 or 6 digits) must fold identically to the 4-digit form.
		{
			input: "\\u{0ff01}",
			want:  "!",
		},
		{
			input: "\\u{00ff01}",
			want:  "!",
		},
		{
			input: "\\u{0ff5e}",
			want:  "~",
		},
		{
			input: "\\u{000061}",
			want:  "a",
		},
		{
			// 7 hex digits exceeds the 6-digit maximum: malformed, falls
			// through to the generic escape handling unchanged.
			input: "\\u{1234567}",
			want:  "u{1234567}",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := jsDecode(tt.input)
			if err != nil {
				t.Error(err)
			}
			if tt.input == tt.want && changed || tt.input != tt.want && !changed {
				t.Errorf("input %q, have %q with changed %t", tt.input, have, changed)
			}
			if have != tt.want {
				t.Errorf("have %q, want %q", have, tt.want)
			}
		})
	}
}

func BenchmarkJSDecode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"\\a\\b\\f\\n\\r\\t\\v\\u0000\\?\\'\\\"\\0\\12\\123\\x00\\xff",
		"\\u{61}\\u{6c}\\u{65}\\u{72}\\u{74}",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := jsDecode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
