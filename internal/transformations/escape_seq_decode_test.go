// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
			require.NoError(t, err)

			shouldChange := tt.input != tt.want
			require.Equalf(t, shouldChange, changed, "unexpected changed value, want %t, have %t", shouldChange, changed)
			require.Equal(t, tt.want, have)
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
				_, _, err := escapeSeqDecode(tt)
				require.NoError(b, err)
			}
		})
	}
}
