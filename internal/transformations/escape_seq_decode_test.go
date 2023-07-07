// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestEscapeSeqDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "TestCase",
			want:  "TestCase",
		},
		{
			input: "\\",
			want:  "\\",
		},
		{
			input: "\\\\u0000",
			want:  "\\u0000",
		},
		{
			input: "\\a\\b\\f\\n\\r\\t\\v\\u0000\\?\\'\\\"\\0\\12\\123\\x00\\xff",
			want:  "\a\b\f\n\r\t\vu0000?'\"\x00\nS\x00\xff",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := escapeSeqDecode(tt.input)
			if err != nil {
				t.Fatal(err)
			}

			shouldChange := tt.input != tt.want
			if changed != shouldChange {
				t.Errorf("unexpected changed value, want %t, have %t", shouldChange, changed)
			}

			if have != tt.want {
				t.Errorf("unexpected value, want %q, have %q", tt.want, have)
			}
		})
	}
}

func BenchmarkEscapeSeqDecode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"\\a\\b\\f\\n\\r\\t\\v\\u0000\\?\\'\\\"\\0\\12\\123\\x00\\xff",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := escapeSeqDecode(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
