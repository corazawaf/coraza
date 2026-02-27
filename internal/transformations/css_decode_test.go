// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCSSDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "Test\u0000Case",
			want:  "Test\u0000Case",
		},
		{
			input: "test\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\\u0000\\12\\123\\1234\\12345\\123456\\ff01\\ff5e\\\n\\\u0000  string",
			want:  "test\n\u000b\u000fnrtv?'\"\u0000\u0012#4EV!~\u0000  string",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := cssDecode(tt.input)
			require.NoError(t, err)

			shouldChange := tt.input != tt.want
			require.Equalf(t, shouldChange, changed, "unexpected changed value, want %t, have %t", shouldChange, changed)
			require.Equal(t, tt.want, have)
		})
	}
}

func BenchmarkCSSDecode(b *testing.B) {
	tests := []string{
		"",
		"hello world",
		"test\\a\\b\\f\\n\\r\\t\\v\\?\\'\\\"\\\u0000\\12\\123\\1234\\12345\\123456\\ff01\\ff5e\\\n\\\u0000  string",
	}

	for _, tc := range tests {
		tt := tc
		b.Run(tt, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := cssDecode(tt)
				require.NoError(b, err)
			}
		})
	}
}
