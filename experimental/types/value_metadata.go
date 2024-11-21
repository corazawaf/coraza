// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package types

import (
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
	}
	return 0, false
}

// DataMetadataList is a list of ValueMetadata.
type DataMetadataList struct {
	metadata map[DataMetadata]bool
}

func (v *DataMetadataList) Evaluate(data string) {
	// we do the analysis only once
	if v.metadata == nil {
		v.metadata = make(map[DataMetadata]bool)
		v.evaluateNumeric(data)
		v.evaluateBoolean(data)
		v.evaluateAlphanumeric(data)
		v.evaluateAscii(data)
		v.evaluateBase64(data)
		// v.evaluateURI(data)
		// v.evaluateDomain(data)
		// v.evaluateUnicode(data)
	}
}

func (v *DataMetadataList) evaluateAlphanumeric(data string) bool {
	for _, c := range data {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) {
			v.metadata[ValueMetadataAlphanumeric] = false
			break
		}
	}
	return v.metadata[ValueMetadataAlphanumeric]
}

func (v *DataMetadataList) evaluateAscii(data string) bool {
	res := true
	for i := 0; i < len(data); i++ {
		if data[i] > unicode.MaxASCII {
			res = false
			break
		}
	}
	v.metadata[ValueMetadataAscii] = res
	return res
}

func isBase64(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/'
}

func (v *DataMetadataList) evaluateBase64(data string) bool {
	res := true
	for i := 0; i < len(data); i++ {
		if !isBase64(data[i]) {
			res = false
			break
		}
	}
	v.metadata[ValueMetadataBase64] = res
	return res
}

func (v *DataMetadataList) evaluateNumeric(data string) bool {
	res := true
	for _, c := range data {
		if !unicode.IsNumber(c) {
			res = false
			break
		}
	}
	v.metadata[ValueMetadataNumeric] = res
	return res
}

func (v *DataMetadataList) evaluateBoolean(data string) bool {
	res := false
	if data == "true" || data == "false" {
		res = true
	}
	v.metadata[ValueMetadataBoolean] = res
	return res
}

func (v *DataMetadataList) IsInScope(metadataTypes []DataMetadata) bool {
	for _, metadataType := range metadataTypes {
		if v.metadata[metadataType] {
			return true
		}
	}
	return false
}
