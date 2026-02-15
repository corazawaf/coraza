// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
			require.NoError(t, err)
			if tt.input == tt.want && changed {
				require.Failf(t, "unexpected changed value", "input %q, have %q with changed %t", tt.input, have, changed)
			}
			require.Equal(t, tt.want, have)
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
				_, _, err := compressWhitespace(tt)
				require.NoError(b, err)
			}
		})
	}
}
