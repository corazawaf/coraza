//go:build tinygo
// +build tinygo

package main

import (
	"encoding/xml"
	"fmt"
	"testing"
)

// TestXMLValidation tests XML validation
func TestXMLValidation(t *testing.T) {
	// Valid XML with properly nested tags
	validXML := `<?xml version="1.0" encoding="UTF-8"?><person><name>John</name></person>`
	if !isValidXML(validXML) {
		t.Errorf("Valid XML incorrectly marked as invalid")
	}
	
	// XML with syntax error - missing closing tag
	invalidXML := `<?xml version="1.0" encoding="UTF-8"?><person><name>John</person>`
	if isValidXML(invalidXML) {
		t.Errorf("Invalid XML incorrectly marked as valid")
	}
}

// isValidXML performs basic XML validation for TinyGo
func isValidXML(data string) bool {
	if err := xml.Unmarshal([]byte(data), new(interface{})); err != nil {
		fmt.Printf("XML validation error: %v\n", err)
		return false
	}
	return true
}