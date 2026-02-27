// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLength(t *testing.T) {
	tests := []struct {
		input  string
		length string
	}{
		{
			input:  "hello",
			length: "5",
		},
		{
			input:  "",
			length: "0",
		},
		{
			input:  "ハローワールド",
			length: "21",
		},
		// length("1") will be a corner case that returns changed = true. Conceptually the transformation
		// returns the length of the string, so it might be considered a change.
		// {
		// 	input:  "1",
		// 	length: "1",
		// },
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.input, func(t *testing.T) {
			have, changed, err := length(tt.input)
			require.NoError(t, err)
			if tt.input == have && changed {
				require.Failf(t, "unexpected changed value", "input %q, have %q with changed %t", tt.input, have, changed)
			}
			require.Equal(t, tt.length, have)
		})
	}
}
