// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "testing"

func TestCompressWhiteSpace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "Single space",
			want:  "Single space",
		},
		{
			input: "Multiple    spaces",
			want:  "Multiple spaces",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := compressWhitespace(tt.input)
			if err != nil {
				t.Error(err)
			}
			if tt.input == tt.want && changed {
				t.Errorf("input %q, have %q with changed %t", tt.input, have, changed)
			}
			if have != tt.want {
				t.Errorf("have %q, want %q", have, tt.want)
			}
		})
	}
}

func BenchmarkCompressWhitespace(b *testing.B) {
	tests := []string{
		"",
		"test",
		"test case",
		"test    case",
		"\ttest  c\n\ras\t  ",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := compressWhitespace(tt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
