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

// NewValueMetadata returns a new ValueMetadata from a string.
func NewValueMetadata(metadata string) (DataMetadata, bool) {
	switch metadata {
	case "numeric":
		return ValueMetadataNumeric, true
	case "boolean":
		return ValueMetadataBoolean, true
	case "alphanumeric":
		return ValueMetadataAlphanumeric, true
	case "ascii":
		return ValueMetadataAscii, true
	case "base64":
		return ValueMetadataBase64, true
	case "uri":
		return ValueMetadataURI, true
	case "domain":
		return ValueMetadataDomain, true
	case "unicode":
		return ValueMetadataUnicode, true
	case "not_numeric":
		return NotValueMetadataNumeric, true
	case "not_boolean":
		return NotValueMetadataBoolean, true
	case "not_alphanumeric":
		return NotValueMetadataAlphanumeric, true
	case "not_ascii":
		return NotValueMetadataAscii, true
	case "not_base64":
		return NotValueMetadataBase64, true
	case "not_uri":
		return NotValueMetadataURI, true
	case "not_domain":
		return NotValueMetadataDomain, true
	case "not_unicode":
		return NotValueMetadataUnicode, true
	}
	return 0, false
}

// DataMetadataList is a list of ValueMetadata.
type DataMetadataList struct {
	metadata  map[DataMetadata]bool
	evaluated map[DataMetadata]bool
	completed bool
}

func NewDataMetadataList() DataMetadataList {
	dataList := DataMetadataList{
		metadata: make(map[DataMetadata]bool),
	}
	dataList.evaluated[ValueMetadataAlphanumeric] = false
	dataList.evaluated[ValueMetadataAscii] = false
	dataList.evaluated[ValueMetadataBase64] = false
	dataList.evaluated[ValueMetadataURI] = false
	dataList.evaluated[ValueMetadataNumeric] = false
	dataList.evaluated[ValueMetadataBoolean] = false
	dataList.evaluated[ValueMetadataUnicode] = false

	return dataList
}

// Evaluator is a function that evaluates metadata.
type Evaluator func(data string, metadata *map[DataMetadata]bool)

// Evaluators map links metadata to evaluation functions.
var Evaluators = map[DataMetadata]Evaluator{
	ValueMetadataAlphanumeric: evaluateAlphanumeric,
	ValueMetadataAscii:        evaluateAscii,
	ValueMetadataBase64:       evaluateBase64,
	ValueMetadataURI:          evaluateURI,
	ValueMetadataNumeric:      evaluateNumeric,
	ValueMetadataBoolean:      evaluateBoolean,
	ValueMetadataUnicode:      evaluateUnicode,
}

func contains(metadata DataMetadata, list []DataMetadata) bool {
	for _, v := range list {
		if v == metadata {
			return true
		}
	}
	return false
}
func (v *DataMetadataList) EvaluateMetadata(data string, allowedMetadatas []DataMetadata) {
	if v != nil && !v.completed {
		for metadataType, evaluator := range Evaluators {
			if contains(metadataType, allowedMetadatas) {
				if v.evaluated[metadataType] {
					continue
				} else {
					evaluator(data, &v.metadata)
					v.evaluated[metadataType] = true
				}
			}
		}
	}
}

func evaluateAlphanumeric(data string, metadata *map[DataMetadata]bool) {
	isAlphanumeric := true
	for _, c := range data {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) && !unicode.IsSpace(c) {
			isAlphanumeric = false
			break
		}
	}
	(*metadata)[ValueMetadataAlphanumeric] = isAlphanumeric
	(*metadata)[NotValueMetadataAlphanumeric] = !isAlphanumeric
}

func evaluateAscii(data string, metadata *map[DataMetadata]bool) {
	isAscii := true
	for i := 0; i < len(data); i++ {
		if data[i] > unicode.MaxASCII {
			isAscii = false
			break
		}
	}
	(*metadata)[ValueMetadataAscii] = isAscii
	(*metadata)[NotValueMetadataAscii] = !isAscii
}

func evaluateBase64(data string, metadata *map[DataMetadata]bool) {
	isBase64 := true
	for i := 0; i < len(data); i++ {
		if !((data[i] >= 'A' && data[i] <= 'Z') || (data[i] >= 'a' && data[i] <= 'z') || (data[i] >= '0' && data[i] <= '9') || data[i] == '+' || data[i] == '/') {
			isBase64 = false
			break
		}
	}
	(*metadata)[ValueMetadataBase64] = isBase64
	(*metadata)[NotValueMetadataBase64] = !isBase64
}

func evaluateURI(data string, metadata *map[DataMetadata]bool) {
	u, err := url.Parse(data)
	isURI := err == nil && u.Scheme != "" && u.Host != ""
	(*metadata)[ValueMetadataURI] = isURI
	(*metadata)[NotValueMetadataURI] = !isURI
}

func evaluateNumeric(data string, metadata *map[DataMetadata]bool) {
	isNumeric := true
	for _, c := range data {
		if !unicode.IsNumber(c) {
			isNumeric = false
			break
		}
	}
	(*metadata)[ValueMetadataNumeric] = isNumeric
	(*metadata)[NotValueMetadataNumeric] = !isNumeric
}

func evaluateBoolean(data string, metadata *map[DataMetadata]bool) {
	isBoolean := data == "true" || data == "false"
	(*metadata)[ValueMetadataBoolean] = isBoolean
	(*metadata)[NotValueMetadataBoolean] = !isBoolean
}

func evaluateUnicode(data string, metadata *map[DataMetadata]bool) {
	isUnicode := false
	for _, c := range data {
		if c > unicode.MaxASCII {
			isUnicode = true
			break
		}
	}
	(*metadata)[ValueMetadataUnicode] = isUnicode
	(*metadata)[NotValueMetadataUnicode] = !isUnicode
}

func (v *DataMetadataList) IsInScope(metadataTypes []DataMetadata) bool {
	for _, metadataType := range metadataTypes {
		if v.metadata[metadataType] {
			return true
		}
	}
	return false
}
