package types

import (
	"testing"
)

func TestIsInScope(t *testing.T) {
	tests := []struct {
		name           string
		evaluationMap  map[DataMetadata]EvaluationData
		metadataTypes  []DataMetadata
		expectedResult bool
	}{
		{
			name: "matches positive metadata requirement",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric},
			expectedResult: true,
		},
		{
			name: "matches negative metadata requirement when value is false",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: false},
			},
			metadataTypes:  []DataMetadata{NotValueMetadataAlphanumeric},
			expectedResult: true,
		},
		{
			name: "fails when positive requirement not satisfied",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: false},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric},
			expectedResult: false,
		},
		{
			name: "fails when negative requirement not satisfied",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{NotValueMetadataAlphanumeric},
			expectedResult: false,
		},
		{
			name: "matches with multiple metadata types when at least one matches",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
				ValueMetadataAscii:        {Evaluated: true, Result: false},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAscii, ValueMetadataAlphanumeric},
			expectedResult: true,
		},
		{
			name: "fails with empty metadata requirements",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{},
			expectedResult: false,
		},
		{
			name:           "fails with empty evaluation map",
			evaluationMap:  map[DataMetadata]EvaluationData{},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric},
			expectedResult: false,
		},
		{
			name: "mixed positive and negative requirements with partial match",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataUnicode: {Evaluated: true, Result: false},
				ValueMetadataNumeric: {Evaluated: true, Result: true},
				ValueMetadataBoolean: {Evaluated: true, Result: false},
			},
			metadataTypes: []DataMetadata{
				NotValueMetadataUnicode,
				ValueMetadataNumeric,
				NotValueMetadataBoolean,
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadataList := DataMetadataList{
				EvaluationMap: tt.evaluationMap,
			}
			result := metadataList.IsInScope(tt.metadataTypes)
			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}

func TestEvaluateMetadata_OnlyEvaluatesRequiredTypes(t *testing.T) {
	testCases := []struct {
		name             string
		allowedMetadatas []DataMetadata
		data             string
		description      string
	}{
		{
			name:             "alphanumeric data with numeric and alphanumeric requirements",
			allowedMetadatas: []DataMetadata{ValueMetadataAlphanumeric, ValueMetadataNumeric},
			data:             "abc123",
			description:      "Should evaluate both alphanumeric and numeric checks",
		},
		{
			name:             "numeric data with boolean requirement",
			allowedMetadatas: []DataMetadata{ValueMetadataBoolean},
			data:             "123456",
			description:      "Should only evaluate boolean check, not numeric",
		},
		{
			name:             "unicode text with negative numeric requirement",
			allowedMetadatas: []DataMetadata{ValueMetadataUnicode, NotValueMetadataNumeric},
			data:             "你好世界",
			description:      "Should evaluate unicode and numeric (for negative check)",
		},
		{
			name:             "base64 string with URI exclusion",
			allowedMetadatas: []DataMetadata{ValueMetadataBase64, NotValueMetadataURI},
			data:             "SGVsbG8gV29ybGQ=",
			description:      "Should evaluate base64 and URI checks",
		},
	}

	allMetadataTypes := []DataMetadata{
		ValueMetadataAlphanumeric,
		ValueMetadataAscii,
		ValueMetadataBase64,
		ValueMetadataURI,
		ValueMetadataDomain,
		ValueMetadataNumeric,
		ValueMetadataBoolean,
		ValueMetadataUnicode,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadataList := NewDataMetadataList()
			metadataList.EvaluateMetadata(tc.data, tc.allowedMetadatas)

			for _, metadata := range allMetadataTypes {
				shouldBeEvaluated := isMetadataRequired(metadata, tc.allowedMetadatas)
				wasEvaluated := metadataList.EvaluationMap[metadata].Evaluated

				if shouldBeEvaluated && !wasEvaluated {
					t.Errorf("metadata %v should have been evaluated but wasn't", metadata)
				}
				if !shouldBeEvaluated && wasEvaluated {
					t.Errorf("metadata %v should not have been evaluated but was", metadata)
				}
			}
		})
	}
}

func isMetadataRequired(metadata DataMetadata, allowedMetadatas []DataMetadata) bool {
	for _, allowed := range allowedMetadatas {
		// Check if this is a negative metadata type
		if positiveType, isNegative := MetadataMap[allowed]; isNegative {
			if positiveType == metadata {
				return true
			}
		} else if allowed == metadata {
			return true
		}
	}
	return false
}

func TestEvaluateMetadata_IntegrationTest(t *testing.T) {
	testCases := []struct {
		name         string
		data         string
		requirements []DataMetadata
		expected     map[DataMetadata]bool
	}{
		{
			name:         "alphanumeric string evaluation",
			data:         "abc123",
			requirements: []DataMetadata{ValueMetadataAlphanumeric, ValueMetadataAscii, ValueMetadataNumeric},
			expected: map[DataMetadata]bool{
				ValueMetadataAlphanumeric: true,
				ValueMetadataAscii:        true,
				ValueMetadataNumeric:      false, // Contains letters
			},
		},
		{
			name:         "pure numeric string evaluation",
			data:         "123456",
			requirements: []DataMetadata{ValueMetadataNumeric, ValueMetadataAlphanumeric, ValueMetadataBoolean},
			expected: map[DataMetadata]bool{
				ValueMetadataNumeric:      true,
				ValueMetadataAlphanumeric: true,  // Numbers are alphanumeric
				ValueMetadataBoolean:      false, // Not "true" or "false"
			},
		},
		{
			name:         "unicode string evaluation",
			data:         "café",
			requirements: []DataMetadata{ValueMetadataUnicode, ValueMetadataAscii, ValueMetadataAlphanumeric},
			expected: map[DataMetadata]bool{
				ValueMetadataUnicode:      true,  // Contains non-ASCII characters
				ValueMetadataAscii:        false, // Contains unicode
				ValueMetadataAlphanumeric: true,  // Unicode letters count as alphanumeric
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadataList := NewDataMetadataList()
			metadataList.EvaluateMetadata(tc.data, tc.requirements)

			for metadataType, expectedResult := range tc.expected {
				evaluation := metadataList.EvaluationMap[metadataType]
				if !evaluation.Evaluated {
					t.Errorf("metadata %v should have been evaluated", metadataType)
					continue
				}
				if evaluation.Result != expectedResult {
					t.Errorf("metadata %v: expected %v, got %v", metadataType, expectedResult, evaluation.Result)
				}
			}
		})
	}
}

func TestEvaluateUnicode(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"ascii only text", "hello world", false},
		{"text with accented characters", "café naïve", true},
		{"text with emoji", "hello 😀 world", true},
		{"chinese characters", "你好世界", true},
		{"mathematical symbols", "∑∏∆", true},
		{"mixed ascii and unicode", "test café", true},
		{"ascii with unicode whitespace", "hello\u00A0world", true}, // Non-breaking space
		{"empty string", "", false},
		{"ascii numbers only", "12345", false},
		{"ascii special characters", "!@#$%^&*()", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateUnicode(tc.input, metadata)

			result := metadata[ValueMetadataUnicode]
			if !result.Evaluated {
				t.Error("unicode evaluation should be marked as evaluated")
			}
			if result.Result != tc.expected {
				t.Errorf("expected %v, got %v for input %q", tc.expected, result.Result, tc.input)
			}
		})
	}
}

func TestEvaluateBase64(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid base64 string", "SGVsbG9Xb3JsZA", true},
		{"base64 with padding characters", "SGVsbG8=", false}, // Contains = which is not allowed in this implementation
		{"letters and numbers only", "ABCDabcd1234", true},
		{"with plus and slash", "ABC+/123", true},
		{"with invalid characters", "Hello@World", false},
		{"with whitespace", "ABC 123", false},
		{"empty string", "", true},
		{"only letters", "abcdefghijklmnopqrstuvwxyz", true},
		{"only numbers", "0123456789", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateBase64(tc.input, metadata)

			result := metadata[ValueMetadataBase64]
			if !result.Evaluated {
				t.Error("base64 evaluation should be marked as evaluated")
			}
			if result.Result != tc.expected {
				t.Errorf("expected %v, got %v for input %q", tc.expected, result.Result, tc.input)
			}
		})
	}
}

func TestEvaluateAlphanumeric(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"letters and numbers", "abc123XYZ", true},
		{"with spaces", "hello world 123", true},
		{"unicode letters", "café123", true},
		{"with punctuation", "hello!", false},
		{"with special symbols", "abc@123", false},
		{"only spaces", "   ", true},
		{"empty string", "", true},
		{"mixed unicode and ascii", "test测试123", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateAlphanumeric(tc.input, metadata)

			result := metadata[ValueMetadataAlphanumeric]
			if !result.Evaluated {
				t.Error("alphanumeric evaluation should be marked as evaluated")
			}
			if result.Result != tc.expected {
				t.Errorf("expected %v, got %v for input %q", tc.expected, result.Result, tc.input)
			}
		})
	}
}

func TestEvaluateAscii(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"standard ascii text", "Hello World!", true},
		{"ascii with numbers and symbols", "Test123!@#", true},
		{"with unicode characters", "Hello Wørld", false},
		{"with high ascii character", "test\u0080", false},
		{"empty string", "", true},
		{"all ascii printable characters", "ABCabc123!@#$%^&*()", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateAscii(tc.input, metadata)

			result := metadata[ValueMetadataAscii]
			if !result.Evaluated {
				t.Error("ascii evaluation should be marked as evaluated")
			}
			if result.Result != tc.expected {
				t.Errorf("expected %v, got %v for input %q", tc.expected, result.Result, tc.input)
			}
		})
	}
}

func TestEvaluateNumeric(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"all digits", "12345", true},
		{"arabic numerals", "١٢٣", true}, // Unicode digits
		{"with letters", "123a", false},
		{"with decimal point", "123.45", false},
		{"with negative sign", "-123", false},
		{"with spaces", "1 2 3", false},
		{"empty string", "", true},
		{"mixed unicode digits", "123४५६", true}, // Mix of ASCII and Devanagari digits
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateNumeric(tc.input, metadata)

			result := metadata[ValueMetadataNumeric]
			if !result.Evaluated {
				t.Error("numeric evaluation should be marked as evaluated")
			}
			if result.Result != tc.expected {
				t.Errorf("expected %v, got %v for input %q", tc.expected, result.Result, tc.input)
			}
		})
	}
}

func TestEvaluateBoolean(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"lowercase true", "true", true},
		{"lowercase false", "false", true},
		{"capitalized true", "True", false},
		{"uppercase false", "FALSE", false},
		{"number one", "1", false},
		{"number zero", "0", false},
		{"empty string", "", false},
		{"random text", "maybe", false},
		{"boolean with spaces", " true ", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateBoolean(tc.input, metadata)

			result := metadata[ValueMetadataBoolean]
			if !result.Evaluated {
				t.Error("boolean evaluation should be marked as evaluated")
			}
			if result.Result != tc.expected {
				t.Errorf("expected %v, got %v for input %q", tc.expected, result.Result, tc.input)
			}
		})
	}
}

func TestEvaluateURI(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"http url", "http://example.com", true},
		{"https url with path", "https://example.com/path/to/resource", true},
		{"ftp url", "ftp://files.example.com", true},
		{"custom scheme", "myapp://action/path", true},
		{"url with query parameters", "https://example.com?param=value", true},
		{"just domain name", "example.com", false},
		{"scheme without host", "http://", false},
		{"invalid format", "not a url at all", false},
		{"empty string", "", false},
		{"malformed url", "http:///invalid", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateURI(tc.input, metadata)

			result := metadata[ValueMetadataURI]
			if !result.Evaluated {
				t.Error("URI evaluation should be marked as evaluated")
			}
			if result.Result != tc.expected {
				t.Errorf("expected %v, got %v for input %q", tc.expected, result.Result, tc.input)
			}
		})
	}
}

func TestNewValueMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected DataMetadata
		ok       bool
	}{
		{"unicode metadata", "unicode", ValueMetadataUnicode, true},
		{"negative unicode", "not_unicode", NotValueMetadataUnicode, true},
		{"alphanumeric metadata", "alphanumeric", ValueMetadataAlphanumeric, true},
		{"negative alphanumeric", "not_alphanumeric", NotValueMetadataAlphanumeric, true},
		{"invalid metadata type", "invalid_type", 0, false},
		{"empty string", "", 0, false},
		{"partial match", "unic", 0, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, ok := NewValueMetadata(tc.input)
			if ok != tc.ok {
				t.Errorf("expected ok=%v, got ok=%v", tc.ok, ok)
			}
			if result != tc.expected {
				t.Errorf("expected result=%v, got result=%v", tc.expected, result)
			}
		})
	}
}
