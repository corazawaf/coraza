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

// Check if metadata is in a list of allowed metadata types
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
