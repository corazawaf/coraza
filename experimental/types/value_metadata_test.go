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
			name: "Positive metadata matches",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric},
			expectedResult: true,
		},
		{
			name: "Negative metadata matches",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: false},
			},
			metadataTypes:  []DataMetadata{NotValueMetadataAlphanumeric},
			expectedResult: true,
		},
		{
			name: "No match in positive metadata",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: false},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric},
			expectedResult: false,
		},
		{
			name: "No match in negative metadata",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{NotValueMetadataAlphanumeric},
			expectedResult: false,
		},
		{
			name: "Multiple metadata, one match",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
				ValueMetadataAscii:        {Evaluated: true, Result: false},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAscii, ValueMetadataAlphanumeric},
			expectedResult: true,
		},
		{
			name: "Empty metadata types",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{},
			expectedResult: false,
		},
		{
			name:           "Evaluation map empty",
			evaluationMap:  map[DataMetadata]EvaluationData{},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric},
			expectedResult: false,
		},
		{
			name: "Unrelated metadata present",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAscii: {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric},
			expectedResult: false,
		},
		{
			name: "Multiple negative metadata, one match",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: false},
				ValueMetadataAscii:        {Evaluated: true, Result: true},
				ValueMetadataBase64:       {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{NotValueMetadataAlphanumeric, NotValueMetadataBase64},
			expectedResult: true,
		},
		{
			name: "All metadata match",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: true},
				ValueMetadataAscii:        {Evaluated: true, Result: true},
				ValueMetadataNumeric:      {Evaluated: true, Result: true},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric, ValueMetadataAscii, ValueMetadataNumeric},
			expectedResult: true,
		},
		{
			name: "All negative metadata match",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: false},
				ValueMetadataAscii:        {Evaluated: true, Result: false},
			},
			metadataTypes:  []DataMetadata{NotValueMetadataAlphanumeric, NotValueMetadataAscii},
			expectedResult: true,
		},
		{
			name: "Interleaved positive and negative metadata",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataUnicode: {Evaluated: true, Result: false},
				ValueMetadataNumeric: {Evaluated: true, Result: true},
				ValueMetadataBoolean: {Evaluated: true, Result: false},
				ValueMetadataBase64:  {Evaluated: true, Result: true},
			},
			metadataTypes: []DataMetadata{
				NotValueMetadataUnicode, ValueMetadataNumeric,
				NotValueMetadataBoolean, NotValueMetadataBase64,
			},
			expectedResult: true, // Matches Numeric positively and Unicode negatively
		},
		{
			name: "Edge case: All false evaluations",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataAlphanumeric: {Evaluated: true, Result: false},
				ValueMetadataAscii:        {Evaluated: true, Result: false},
				ValueMetadataNumeric:      {Evaluated: true, Result: false},
			},
			metadataTypes:  []DataMetadata{ValueMetadataAlphanumeric, ValueMetadataAscii, ValueMetadataNumeric},
			expectedResult: false,
		},
		{
			name: "Complex mixed metadata types with no match",
			evaluationMap: map[DataMetadata]EvaluationData{
				ValueMetadataUnicode: {Evaluated: true, Result: false},
				ValueMetadataNumeric: {Evaluated: true, Result: false},
				ValueMetadataAscii:   {Evaluated: true, Result: false},
			},
			metadataTypes: []DataMetadata{
				NotValueMetadataBoolean, NotValueMetadataBase64,
				ValueMetadataDomain,
			},
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadataList := DataMetadataList{
				EvaluationMap: test.evaluationMap,
			}
			result := metadataList.IsInScope(test.metadataTypes)
			if result != test.expectedResult {
				t.Errorf("expected %v, got %v", test.expectedResult, result)
			}
		})
	}
}

func TestNecessaryEvaluations(t *testing.T) {
	// Here, we make sure we only test what is necessary
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

	tests := []struct {
		name             string
		allowedMetadatas []DataMetadata
		data             string
	}{
		{
			name:             "Alphanumeric and Numeric",
			allowedMetadatas: []DataMetadata{ValueMetadataAlphanumeric, ValueMetadataNumeric},
			data:             "abc123",
		},
		{
			name:             "Numeric and Boolean",
			allowedMetadatas: []DataMetadata{ValueMetadataNumeric, ValueMetadataBoolean},
			data:             "123456",
		},
		{
			name:             "Boolean and ASCII",
			allowedMetadatas: []DataMetadata{ValueMetadataBoolean, ValueMetadataAscii},
			data:             "true",
		},
		{
			name:             "ASCII and Base64",
			allowedMetadatas: []DataMetadata{ValueMetadataAscii, ValueMetadataBase64},
			data:             "SGVsbG8gV29ybGQ=", // Base64 string for "Hello World"
		},
		{
			name:             "URI and Domain",
			allowedMetadatas: []DataMetadata{ValueMetadataURI},
			data:             "https://www.example.com",
		},
		{
			name:             "Unicode and Not Numeric",
			allowedMetadatas: []DataMetadata{ValueMetadataUnicode, NotValueMetadataNumeric},
			data:             "你好", // Unicode characters
		},
		{
			name:             "Alphanumeric and Not Boolean",
			allowedMetadatas: []DataMetadata{ValueMetadataAlphanumeric, NotValueMetadataBoolean},
			data:             "abc123",
		},
		{
			name:             "Not Alphanumeric and Not ASCII",
			allowedMetadatas: []DataMetadata{NotValueMetadataAlphanumeric, NotValueMetadataAscii},
			data:             "!@#$%^&*()",
		},
		{
			name:             "Base64 and Not URI",
			allowedMetadatas: []DataMetadata{ValueMetadataBase64, NotValueMetadataURI},
			data:             "SGVsbG8gV29ybGQ=", // Base64 encoded string
		},
		// {
		// 	name:             "Not Domain and Not Unicode",
		// 	allowedMetadatas: []DataMetadata{NotValueMetadataDomain, NotValueMetadataUnicode},
		// 	data:             "ASCII123",
		// },
	}

	for _, test := range tests {
		metadataList := NewDataMetadataList()
		metadataList.EvaluateMetadata(test.data, test.allowedMetadatas)
		for _, metadata := range allMetadataTypes {
			if checkIfMetadataInList(metadata, test.allowedMetadatas) {
				if !metadataList.EvaluationMap[metadata].Evaluated {
					t.Errorf("Expected metadata %v to be evaluated, but it was not, allowed = %v", metadata, test.allowedMetadatas)
				}
			} else {
				if metadataList.EvaluationMap[metadata].Evaluated {
					t.Errorf("Expected metadata %v to not be evaluated, but it was", metadata)
				}
			}
		}
	}
}

func checkIfMetadataInList(metadata DataMetadata, allowedMetadatas []DataMetadata) bool {
	for _, meta := range allowedMetadatas {
		// Check if meta is negative, if so check if it is the negative of the metadata
		if positiveType, isNegative := MetadataMap[meta]; isNegative {
			if positiveType == metadata {
				return true
			}
		} else if meta == metadata {
			return true
		}
	}
	return false
}

func TestEvaluateMultipleMetadata(t *testing.T) {
	dataList := NewDataMetadataList()
	dataList.EvaluateMetadata("abc123", []DataMetadata{ValueMetadataAlphanumeric, ValueMetadataAscii, ValueMetadataNumeric})

	if !dataList.EvaluationMap[ValueMetadataAlphanumeric].Result {
		t.Errorf("Expected alphanumeric evaluation to be true, but got false")
	}

	if !dataList.EvaluationMap[ValueMetadataAscii].Result {
		t.Errorf("Expected ascii evaluation to be true, but got false")
	}
	if dataList.EvaluationMap[ValueMetadataNumeric].Result {
		t.Errorf("Expected numeric evaluation to be false, but got true")
	}
	// Make sure that other metadata evaluations are not done
	if dataList.EvaluationMap[ValueMetadataURI].Evaluated {
		t.Errorf("Expected URI evaluation to not be done, but got true")
	}
	if dataList.EvaluationMap[ValueMetadataBoolean].Evaluated {
		t.Errorf("Expected boolean evaluation to not be done, but got true")
	}
}

func TestEvaluateUnicode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "ASCII only string should return false",
			input:    "hello world",
			expected: false,
		},
		{
			name:     "String with unicode characters should return true",
			input:    "héllo wørld",
			expected: true,
		},
		{
			name:     "String with emoji should return true",
			input:    "hello 😀",
			expected: true,
		},
		{
			name:     "String with Chinese characters should return true",
			input:    "你好世界",
			expected: true,
		},
		{
			name:     "Empty string should return false",
			input:    "",
			expected: false,
		},
		{
			name:     "Only ASCII numbers should return false",
			input:    "12345",
			expected: false,
		},
		{
			name:     "ASCII special characters should return false",
			input:    "!@#$%^&*()",
			expected: false,
		},
		{
			name:     "Mixed ASCII and unicode should return true",
			input:    "test café",
			expected: true,
		},
		{
			name:     "Unicode mathematical symbols should return true",
			input:    "∑∏∆",
			expected: true,
		},
		{
			name:     "ASCII with unicode whitespace should return true",
			input:    "hello\u00A0world", // Non-breaking space
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateUnicode(tt.input, metadata)

			result := metadata[ValueMetadataUnicode]
			if !result.Evaluated {
				t.Error("Expected Evaluated to be true")
			}
			if result.Result != tt.expected {
				t.Errorf("Expected Result to be %v, got %v", tt.expected, result.Result)
			}
		})
	}
}

func TestEvaluateBase64(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid base64 characters should return true",
			input:    "SGVsbG9Xb3JsZA",
			expected: true,
		},
		{
			name:     "Invalid base64 with special chars should return false",
			input:    "Hello@World",
			expected: false,
		},
		{
			name:     "Empty string should return true",
			input:    "",
			expected: true,
		},
		{
			name:     "Only letters should return true",
			input:    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
			expected: true,
		},
		{
			name:     "Only numbers should return true",
			input:    "0123456789",
			expected: true,
		},
		{
			name:     "With plus and slash should return true",
			input:    "ABC+/123",
			expected: true,
		},
		{
			name:     "With space should return false",
			input:    "ABC 123",
			expected: false,
		},
		{
			name:     "With equals should return false",
			input:    "ABC=",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateBase64(tt.input, metadata)

			result := metadata[ValueMetadataBase64]
			if !result.Evaluated {
				t.Error("Expected Evaluated to be true")
			}
			if result.Result != tt.expected {
				t.Errorf("Expected Result to be %v, got %v", tt.expected, result.Result)
			}
		})
	}
}

func TestEvaluateAlphanumeric(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Letters and numbers should return true",
			input:    "abc123",
			expected: true,
		},
		{
			name:     "Letters numbers and spaces should return true",
			input:    "abc 123",
			expected: true,
		},
		{
			name:     "Special characters should return false",
			input:    "abc@123",
			expected: false,
		},
		{
			name:     "Empty string should return true",
			input:    "",
			expected: true,
		},
		{
			name:     "Only spaces should return true",
			input:    "   ",
			expected: true,
		},
		{
			name:     "Unicode letters should return true",
			input:    "café",
			expected: true,
		},
		{
			name:     "Punctuation should return false",
			input:    "hello!",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateAlphanumeric(tt.input, metadata)

			result := metadata[ValueMetadataAlphanumeric]
			if !result.Evaluated {
				t.Error("Expected Evaluated to be true")
			}
			if result.Result != tt.expected {
				t.Errorf("Expected Result to be %v, got %v", tt.expected, result.Result)
			}
		})
	}
}

func TestEvaluateAscii(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "ASCII only string should return true",
			input:    "Hello World!",
			expected: true,
		},
		{
			name:     "String with unicode should return false",
			input:    "Hello Wørld",
			expected: false,
		},
		{
			name:     "Empty string should return true",
			input:    "",
			expected: true,
		},
		{
			name:     "ASCII numbers and symbols should return true",
			input:    "123!@#$%",
			expected: true,
		},
		{
			name:     "High ASCII characters should return false",
			input:    "test\u0080",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateAscii(tt.input, metadata)

			result := metadata[ValueMetadataAscii]
			if !result.Evaluated {
				t.Error("Expected Evaluated to be true")
			}
			if result.Result != tt.expected {
				t.Errorf("Expected Result to be %v, got %v", tt.expected, result.Result)
			}
		})
	}
}

func TestEvaluateNumeric(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Only digits should return true",
			input:    "12345",
			expected: true,
		},
		{
			name:     "Empty string should return true",
			input:    "",
			expected: true,
		},
		{
			name:     "Letters should return false",
			input:    "123a",
			expected: false,
		},
		{
			name:     "Special characters should return false",
			input:    "123.45",
			expected: false,
		},
		{
			name:     "Unicode numbers should return true",
			input:    "١٢٣", // Arabic numerals
			expected: true,
		},
		{
			name:     "Negative sign should return false",
			input:    "-123",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateNumeric(tt.input, metadata)

			result := metadata[ValueMetadataNumeric]
			if !result.Evaluated {
				t.Error("Expected Evaluated to be true")
			}
			if result.Result != tt.expected {
				t.Errorf("Expected Result to be %v, got %v", tt.expected, result.Result)
			}
		})
	}
}

func TestEvaluateBoolean(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "String 'true' should return true",
			input:    "true",
			expected: true,
		},
		{
			name:     "String 'false' should return true",
			input:    "false",
			expected: true,
		},
		{
			name:     "String 'True' should return false",
			input:    "True",
			expected: false,
		},
		{
			name:     "String 'FALSE' should return false",
			input:    "FALSE",
			expected: false,
		},
		{
			name:     "Empty string should return false",
			input:    "",
			expected: false,
		},
		{
			name:     "Random string should return false",
			input:    "hello",
			expected: false,
		},
		{
			name:     "Number string should return false",
			input:    "1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateBoolean(tt.input, metadata)

			result := metadata[ValueMetadataBoolean]
			if !result.Evaluated {
				t.Error("Expected Evaluated to be true")
			}
			if result.Result != tt.expected {
				t.Errorf("Expected Result to be %v, got %v", tt.expected, result.Result)
			}
		})
	}
}

func TestEvaluateURI(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid HTTP URL should return true",
			input:    "http://example.com",
			expected: true,
		},
		{
			name:     "Valid HTTPS URL should return true",
			input:    "https://example.com/path",
			expected: true,
		},
		{
			name:     "URL without scheme should return false",
			input:    "example.com",
			expected: false,
		},
		{
			name:     "URL without host should return false",
			input:    "http://",
			expected: false,
		},
		{
			name:     "Invalid URL should return false",
			input:    "not a url",
			expected: false,
		},
		{
			name:     "Empty string should return false",
			input:    "",
			expected: false,
		},
		{
			name:     "FTP URL should return true",
			input:    "ftp://files.example.com",
			expected: true,
		},
		{
			name:     "Custom scheme should return true",
			input:    "custom://host.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := make(map[DataMetadata]EvaluationData)
			evaluateURI(tt.input, metadata)

			result := metadata[ValueMetadataURI]
			if !result.Evaluated {
				t.Error("Expected Evaluated to be true")
			}
			if result.Result != tt.expected {
				t.Errorf("Expected Result to be %v, got %v", tt.expected, result.Result)
			}
		})
	}
}

func TestDataMetadataListEvaluateMetadata(t *testing.T) {
	tests := []struct {
		name              string
		data              string
		allowedMetadatas  []DataMetadata
		expectedResults   map[DataMetadata]bool
		expectedEvaluated map[DataMetadata]bool
	}{
		{
			name:             "Evaluate unicode on ASCII string",
			data:             "hello",
			allowedMetadatas: []DataMetadata{ValueMetadataUnicode},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataUnicode: false,
			},
			expectedEvaluated: map[DataMetadata]bool{
				ValueMetadataUnicode: true,
			},
		},
		{
			name:             "Evaluate unicode on unicode string",
			data:             "héllo",
			allowedMetadatas: []DataMetadata{ValueMetadataUnicode},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataUnicode: true,
			},
			expectedEvaluated: map[DataMetadata]bool{
				ValueMetadataUnicode: true,
			},
		},
		{
			name: "Evaluate multiple metadata types",
			data: "123",
			allowedMetadatas: []DataMetadata{
				ValueMetadataNumeric,
				ValueMetadataAlphanumeric,
				ValueMetadataUnicode,
			},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataNumeric:      true,
				ValueMetadataAlphanumeric: true,
				ValueMetadataUnicode:      false,
			},
			expectedEvaluated: map[DataMetadata]bool{
				ValueMetadataNumeric:      true,
				ValueMetadataAlphanumeric: true,
				ValueMetadataUnicode:      true,
			},
		},
		{
			name:             "Evaluate negative metadata types",
			data:             "hello",
			allowedMetadatas: []DataMetadata{NotValueMetadataNumeric},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataNumeric: false,
			},
			expectedEvaluated: map[DataMetadata]bool{
				ValueMetadataNumeric: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadataList := NewDataMetadataList()
			metadataList.EvaluateMetadata(tt.data, tt.allowedMetadatas)

			for metadataType, expectedResult := range tt.expectedResults {
				result, exists := metadataList.EvaluationMap[metadataType]
				if !exists {
					t.Errorf("Expected metadata type %v to be evaluated", metadataType)
					continue
				}
				if result.Result != expectedResult {
					t.Errorf("Expected result for %v to be %v, got %v", metadataType, expectedResult, result.Result)
				}
			}

			for metadataType, expectedEvaluated := range tt.expectedEvaluated {
				result, exists := metadataList.EvaluationMap[metadataType]
				if !exists {
					t.Errorf("Expected metadata type %v to exist", metadataType)
					continue
				}
				if result.Evaluated != expectedEvaluated {
					t.Errorf("Expected evaluated for %v to be %v, got %v", metadataType, expectedEvaluated, result.Evaluated)
				}
			}
		})
	}
}

func TestNewValueMetadata(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected DataMetadata
		ok       bool
	}{
		{
			name:     "Valid unicode metadata string",
			input:    "unicode",
			expected: ValueMetadataUnicode,
			ok:       true,
		},
		{
			name:     "Valid not_unicode metadata string",
			input:    "not_unicode",
			expected: NotValueMetadataUnicode,
			ok:       true,
		},
		{
			name:     "Invalid metadata string",
			input:    "invalid",
			expected: 0,
			ok:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := NewValueMetadata(tt.input)
			if ok != tt.ok {
				t.Errorf("Expected ok to be %v, got %v", tt.ok, ok)
			}
			if result != tt.expected {
				t.Errorf("Expected result to be %v, got %v", tt.expected, result)
			}
		})
	}
}
