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
		for metadataType := range v.metadata {
			switch metadataType {
			case ValueMetadataNumeric:
				v.evaluateNumeric(data)
			case ValueMetadataBoolean:
				v.evaluateBoolean(data)
			case ValueMetadataAlphanumeric:
				v.evaluateAlphanumeric(data)
			case ValueMetadataAscii:
				v.evaluateAscii(data)
			case ValueMetadataBase64:
				v.evaluateBase64(data)
				// case ValueMetadataURI:
				// 	result = result || v.evaluateURI(data)
				// case ValueMetadataDomain:
				// 	result = result || v.evaluateDomain(data)
				// case ValueMetadataUnicode:
				// 	result = result || v.evaluateUnicode(data)
			}
		}
	}
}

func (v *DataMetadataList) evaluateAlphanumeric(data string) bool {
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
	res := true
	if data == "true" || data == "false" {
		res = true
	}
	v.metadata[ValueMetadataBoolean] = res
	return res
}

func (v *DataMetadataList) TestNumeric() bool {
	return v.metadata[ValueMetadataNumeric]
}

func (v *DataMetadataList) TestBoolean() bool {
	return v.metadata[ValueMetadataBoolean]
}

func (v *DataMetadataList) TestAlphanumeric() bool {
	return v.metadata[ValueMetadataAlphanumeric]
}

func (v *DataMetadataList) TestAscii() bool {
	return v.metadata[ValueMetadataAscii]
}

func (v *DataMetadataList) TestBase64() bool {
	return v.metadata[ValueMetadataBase64]
}

func (v *DataMetadataList) TestURI() bool {
	return v.metadata[ValueMetadataURI]
}

func (v *DataMetadataList) TestDomain() bool {
	return v.metadata[ValueMetadataDomain]
}

func (v *DataMetadataList) TestUnicode() bool {
	return v.metadata[ValueMetadataUnicode]
}

func (v *DataMetadataList) Test(metadataTypes []DataMetadata) bool {
	for _, metadataType := range metadataTypes {
		if !v.metadata[metadataType] {
			return false
		}
	}
	return true
}
