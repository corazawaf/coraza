// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package types

import "unicode"

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
	case "numeric":
		return ValueMetadataNumeric, true
	case "boolean":
		return ValueMetadataBoolean, true
	case "unicode":
		return ValueMetadataUnicode, true
	}
	return 0, false
}

// DataMetadataList is a list of ValueMetadata.
type DataMetadataList struct {
	metadata map[DataMetadata]bool
}

func (v *DataMetadataList) Test(data string, metadataType DataMetadata) bool {
	result, ok := v.metadata[metadataType]
	if !ok {
		// we do the analysis only once
		switch metadataType {
		case ValueMetadataAlphanumeric:
			return v.testAlphanumeric(data)
		default:
			// this should not happen
			return false
		}
	}
	return result

}

func (v *DataMetadataList) testAlphanumeric(data string) bool {
	res := true
	for _, c := range data {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) {
			res = false
			break
		}
	}
	v.metadata[ValueMetadataAlphanumeric] = res
	return res
}
