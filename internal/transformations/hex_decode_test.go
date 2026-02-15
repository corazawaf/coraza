// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHexDecode(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedOutput string
		expectedValid  bool
		expectError    bool
	}{
		{
			name:           "valid hexadecimal string",
			input:          "48656c6c6f",
			expectedOutput: "Hello",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "odd length",
			input:          "48656c6c6f7",
			expectedOutput: "",
			expectedValid:  false,
			expectError:    true,
		},
		{
			name:           "invalid with non hex characters",
			input:          "YyYy",
			expectedOutput: "",
			expectedValid:  false,
			expectError:    true,
		},
		{
			name:           "invalid with extra characters",
			input:          "123G",
			expectedOutput: "",
			expectedValid:  false,
			expectError:    true,
		},
		{
			name:           "empty input",
			input:          "",
			expectedOutput: "",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "uppercase hex string",
			input:          "48454C4C4F",
			expectedOutput: "HELLO",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "mixed case",
			input:          "48454c4C4f",
			expectedOutput: "HELLO",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "special characters",
			input:          "21402324255E262A28",
			expectedOutput: "!@#$%^&*(",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "odd length with invalid character",
			input:          "48656c6c6fZ",
			expectedOutput: "",
			expectedValid:  false,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			output, valid, err := hexDecode(tt.input)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tt.expectedOutput, output)
			require.Equal(t, tt.expectedValid, valid)
		})
	}
}
