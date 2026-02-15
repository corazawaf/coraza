// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveWhiteSpace(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  "",
		},
		{
			input: "test",
			want:  "test",
		},
		{
			input: "t e s t",
			want:  "test",
		},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := removeWhitespace(tt.input)
			require.NoError(t, err)
			if tt.input == tt.want && changed || tt.input != tt.want && !changed {
				require.Failf(t, "unexpected changed value", "input %q, have %q with changed %t", tt.input, have, changed)
			}
			require.Equal(t, tt.want, have)
		})
	}
}
