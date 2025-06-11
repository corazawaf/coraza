// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package types

import (
	"net/url"
	"unicode"
)

// DataMetadata is the type of metadata that a value can have.
type DataMetadata int

const (
	// ValueMetadataAlphanumeric represents an alphanumeric value.
	ValueMetadataAlphanumeric DataMetadata = iota
	// ValueMetadataAscii represents an ASCII value.
	ValueMetadataAscii
	// ValueMetadataBase64 represents a base64 value.
	ValueMetadataBase64
	// ValueMetadataURI represents a URI value.
	ValueMetadataURI
	// ValueMetadataDomain represents a domain value.
	ValueMetadataDomain
	// ValueMetadataNumeric represents a numeric value, either integer or float.
	ValueMetadataNumeric
	// ValueMetadataBoolean represents a boolean value.
	ValueMetadataBoolean
	// ValueMetadataUnicode represents a unicode value.
	ValueMetadataUnicode
	// NotValueMetadataAlphanumeric represents a non-alphanumeric value.
	NotValueMetadataAlphanumeric
	// NotValueMetadataAscii represents a non-ASCII value.
	NotValueMetadataAscii
	// NotValueMetadataBase64 represents a non-base64 value.
	NotValueMetadataBase64
	// NotValueMetadataURI represents a non-URI value.
	NotValueMetadataURI
	// NotValueMetadataDomain represents a non-domain value.
	NotValueMetadataDomain
	// NotValueMetadataNumeric represents a non-numeric value.
	NotValueMetadataNumeric
	// NotValueMetadataBoolean represents a non-boolean value.
	NotValueMetadataBoolean
	// NotValueMetadataUnicode represents a non-unicode value.
	NotValueMetadataUnicode
)

var MetadataMap = map[DataMetadata]DataMetadata{
	NotValueMetadataAlphanumeric: ValueMetadataAlphanumeric,
	NotValueMetadataAscii:        ValueMetadataAscii,
	NotValueMetadataBase64:       ValueMetadataBase64,
	NotValueMetadataURI:          ValueMetadataURI,
	NotValueMetadataDomain:       ValueMetadataDomain,
	NotValueMetadataNumeric:      ValueMetadataNumeric,
	NotValueMetadataBoolean:      ValueMetadataBoolean,
	NotValueMetadataUnicode:      ValueMetadataUnicode,
}

type EvaluationData struct {
	Evaluated bool
	Result    bool
}

// MetadataStrings provides a mapping of strings to metadata for quick lookup.
var metadataStrings = map[string]DataMetadata{
	"numeric":          ValueMetadataNumeric,
	"boolean":          ValueMetadataBoolean,
	"alphanumeric":     ValueMetadataAlphanumeric,
	"ascii":            ValueMetadataAscii,
	"base64":           ValueMetadataBase64,
	"uri":              ValueMetadataURI,
	"domain":           ValueMetadataDomain,
	"unicode":          ValueMetadataUnicode,
	"not_numeric":      NotValueMetadataNumeric,
	"not_boolean":      NotValueMetadataBoolean,
	"not_alphanumeric": NotValueMetadataAlphanumeric,
	"not_ascii":        NotValueMetadataAscii,
	"not_base64":       NotValueMetadataBase64,
	"not_uri":          NotValueMetadataURI,
	"not_domain":       NotValueMetadataDomain,
	"not_unicode":      NotValueMetadataUnicode,
}

// Evaluators provides a mapping of metadata to evaluator functions.
var Evaluators = map[DataMetadata]Evaluator{
	ValueMetadataAlphanumeric: evaluateAlphanumeric,
	ValueMetadataAscii:        evaluateAscii,
	ValueMetadataBase64:       evaluateBase64,
	ValueMetadataURI:          evaluateURI,
	ValueMetadataNumeric:      evaluateNumeric,
	ValueMetadataBoolean:      evaluateBoolean,
	ValueMetadataUnicode:      evaluateUnicode,
}

// NewValueMetadata returns a new ValueMetadata from a string.
func NewValueMetadata(metadata string) (DataMetadata, bool) {
	val, ok := metadataStrings[metadata]
	return val, ok
}

// DataMetadataList holds metadata and its evaluation state.
type DataMetadataList struct {
	EvaluationMap map[DataMetadata]EvaluationData
}

// NewDataMetadataList creates a new DataMetadataList with initialized fields.
func NewDataMetadataList() DataMetadataList {
	return DataMetadataList{
		EvaluationMap: make(map[DataMetadata]EvaluationData),
	}
}

// Evaluator is a function that evaluates metadata.
type Evaluator func(data string, metadata map[DataMetadata]EvaluationData)

// contains checks if a metadata type exists in a slice.
func contains(metadata DataMetadata, allowedMetadatas map[DataMetadata]bool) bool {
	return allowedMetadatas[metadata]
}

// EvaluateMetadata evaluates the allowed metadata types on the data.
func (v *DataMetadataList) EvaluateMetadata(data string, allowedMetadatas []DataMetadata) {
	if v == nil {
		return
	}

	allowedSet := make(map[DataMetadata]bool, len(allowedMetadatas))
	for _, meta := range allowedMetadatas {
		if meta >= NotValueMetadataAlphanumeric {
			allowedSet[meta-NotValueMetadataAlphanumeric] = true
			continue
		}
		allowedSet[meta] = true
	}
	// If Evaluation Map is empty, create one.
	if len(v.EvaluationMap) == 0 {
		v.EvaluationMap = make(map[DataMetadata]EvaluationData)
	}
	for metadataType, evaluator := range Evaluators {
		if contains(metadataType, allowedSet) && !v.EvaluationMap[metadataType].Evaluated {
			evaluator(data, v.EvaluationMap)
		}
	}
}

// Evaluation functions
func evaluateAlphanumeric(data string, metadata map[DataMetadata]EvaluationData) {
	for _, c := range data {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) && !unicode.IsSpace(c) {
			metadata[ValueMetadataAlphanumeric] = EvaluationData{Result: false, Evaluated: true}
			return
		}
	}
	metadata[ValueMetadataAlphanumeric] = EvaluationData{Result: true, Evaluated: true}
}

func evaluateAscii(data string, metadata map[DataMetadata]EvaluationData) {
	for i := 0; i < len(data); i++ {
		if data[i] > unicode.MaxASCII {
			metadata[ValueMetadataAscii] = EvaluationData{Result: false, Evaluated: true}
			return
		}
	}
	metadata[ValueMetadataAscii] = EvaluationData{Result: true, Evaluated: true}
}

func evaluateBase64(data string, metadata map[DataMetadata]EvaluationData) {
	for i := 0; i < len(data); i++ {
		if !(data[i] >= 'A' && data[i] <= 'Z' ||
			data[i] >= 'a' && data[i] <= 'z' ||
			data[i] >= '0' && data[i] <= '9' ||
			data[i] == '+' || data[i] == '/') {
			metadata[ValueMetadataBase64] = EvaluationData{Result: false, Evaluated: true}
			return
		}
	}
	metadata[ValueMetadataBase64] = EvaluationData{Result: true, Evaluated: true}
}

func evaluateURI(data string, metadata map[DataMetadata]EvaluationData) {
	u, err := url.Parse(data)
	isURI := err == nil && u.Scheme != "" && u.Host != ""
	metadata[ValueMetadataURI] = EvaluationData{Result: isURI, Evaluated: true}
}

func evaluateNumeric(data string, metadata map[DataMetadata]EvaluationData) {
	for _, c := range data {
		if !unicode.IsNumber(c) {
			metadata[ValueMetadataNumeric] = EvaluationData{Result: false, Evaluated: true}
			return
		}
	}
	metadata[ValueMetadataNumeric] = EvaluationData{Result: true, Evaluated: true}
}

func evaluateBoolean(data string, metadata map[DataMetadata]EvaluationData) {
	metadata[ValueMetadataBoolean] = EvaluationData{
		Evaluated: true,
		Result:    data == "true" || data == "false",
	}
}

func evaluateUnicode(data string, metadata map[DataMetadata]EvaluationData) {
	for _, c := range data {
		if c > unicode.MaxASCII {
			metadata[ValueMetadataUnicode] = EvaluationData{Result: true, Evaluated: true}
			return
		}
	}
	metadata[ValueMetadataUnicode] = EvaluationData{Result: false, Evaluated: true}
}

func (v *DataMetadataList) IsInScope(allowedMetadatas []DataMetadata) bool {

	for _, metadataType := range allowedMetadatas {
		if positiveType, isNegative := MetadataMap[metadataType]; isNegative {
			if data, exists := v.EvaluationMap[positiveType]; exists && !data.Result {
				return true
			}
		} else {
			if data, exists := v.EvaluationMap[metadataType]; exists && data.Result {
				return true
			}
		}
	}
	return false
}
