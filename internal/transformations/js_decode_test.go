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
