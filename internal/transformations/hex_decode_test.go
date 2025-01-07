package transformations

import (
	"testing"
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
			name:           "ValidHexadecimalString",
			input:          "48656c6c6f",
			expectedOutput: "Hello",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "ValidHexadecimalStringWithWords",
			input:          "6865786465636f6465",
			expectedOutput: "hexdecode",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "OddLengthHexadecimalString",
			input:          "48656c6c6f7",
			expectedOutput: "Hello",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "InvalidHexadecimalStringWithNonHexCharacters",
			input:          "YYY",
			expectedOutput: "",
			expectedValid:  false,
			expectError:    true,
		},
		{
			name:           "InvalidHexadecimalStringWithExtraCharacters",
			input:          "123G",
			expectedOutput: "",
			expectedValid:  false,
			expectError:    true,
		},
		{
			name:           "EmptyStringInput",
			input:          "",
			expectedOutput: "",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "UppercaseHexString",
			input:          "48454C4C4F",
			expectedOutput: "HELLO",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "MixedCaseHexString",
			input:          "48454c4C4f",
			expectedOutput: "HELLO",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "SpecialCharactersHexString",
			input:          "21402324255E262A28",
			expectedOutput: "!@#$%^&*(",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "LongHexString",
			input:          "48656C6C6F20576F726C642C20746869732069732061206C6F6E67657220737472696E67",
			expectedOutput: "Hello World, this is a longer string",
			expectedValid:  true,
			expectError:    false,
		},
		{
			name:           "MultipleConsecutiveInvalidCharacters",
			input:          "123XYZ789",
			expectedOutput: "",
			expectedValid:  false,
			expectError:    true,
		},
		{
			name:           "OddLengthWithInvalidCharacter",
			input:          "48656c6c6fZ",
			expectedOutput: "Hello",
			expectedValid:  true,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			output, valid, err := hexDecode(tt.input)

			if (err != nil) != tt.expectError {
				t.Errorf("hexDecode(%q): expected error=%v, got error=%v", tt.input, tt.expectError, err)
			}

			if output != tt.expectedOutput {
				t.Errorf("hexDecode(%q): expected output=%q, got output=%q", tt.input, tt.expectedOutput, output)
			}

			if valid != tt.expectedValid {
				t.Errorf("hexDecode(%q): expected valid=%v, got valid=%v", tt.input, tt.expectedValid, valid)
			}
		})
	}
}
