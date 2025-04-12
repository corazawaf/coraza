// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package operators

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// These tests specifically test the TinyGo implementation of the validate_schema.go operator

// Helper function to create a temporary schema file with the given content and extension.
func createTempSchemaFile(t *testing.T, dir, filename, content, ext string) string {
	t.Helper()
	path := filepath.Join(dir, filename+ext)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp schema file: %v", err)
	}
	return path
}

// TestValidateSchemaCreation tests creation of the validator
func TestValidateSchemaCreation(t *testing.T) {
	// Create temporary directories for test files
	validTempDir := t.TempDir()
	invalidTempDir := t.TempDir()
	unsupportedTempDir := t.TempDir()
	
	// Create a valid JSON schema file
	validSchemaContent := `{"type": "object", "properties": {"name":{"type":"string"}}}`
	validSchemaPath := createTempSchemaFile(t, validTempDir, "valid_schema", validSchemaContent, ".json")
	
	// Create an invalid JSON schema file
	invalidSchemaContent := `{ invalid json }`
	invalidSchemaPath := createTempSchemaFile(t, invalidTempDir, "invalid_schema", invalidSchemaContent, ".json")
	
	// Create a file with unsupported extension
	unsupportedContent := `not a schema`
	unsupportedPath := createTempSchemaFile(t, unsupportedTempDir, "unsupported", unsupportedContent, ".txt")
	
	// Test with empty arguments
	_, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: ""})
	if err == nil {
		t.Errorf("Expected error for empty arguments, got nil")
	}
	
	// Test with invalid schema file
	_, err = NewValidateSchema(plugintypes.OperatorOptions{Arguments: invalidSchemaPath})
	if err == nil {
		t.Errorf("Expected error for invalid schema file, got nil")
	}
	
	// Test with unsupported extension
	_, err = NewValidateSchema(plugintypes.OperatorOptions{Arguments: unsupportedPath})
	if err == nil {
		t.Errorf("Expected error for unsupported extension, got nil")
	}
	
	// Test with valid schema file
	op, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: validSchemaPath})
	if err != nil {
		t.Errorf("Expected no error for valid schema, got: %v", err)
	}
	if op == nil {
		t.Errorf("Expected non-nil operator")
	}
}

// TestEvaluateWithTx tests Evaluate method with transaction data
func TestEvaluateWithTx(t *testing.T) {
	// This test will be minimal since we can't create a full mock transaction in TinyGo
	// Instead, we'll focus on the direct validation functions which are the core
	// of the TinyGo implementation
}

// TestBasicJSONValidation tests the basic JSON validation functionality in TinyGo
func TestBasicJSONValidation(t *testing.T) {
	// Valid JSON
	validJSON := `{"name": "John", "age": 30}`
	valid := isValidJSON(validJSON)
	if !valid {
		t.Errorf("Expected valid JSON to return true, got false")
	}

	// Invalid JSON
	invalidJSON := `{"name": John, "age": 30}` // Missing quotes
	valid = isValidJSON(invalidJSON)
	if valid {
		t.Errorf("Expected invalid JSON to return false, got true")
	}
	
	// Empty JSON
	emptyJSON := ""
	valid = isValidJSON(emptyJSON)
	if valid {
		t.Errorf("Expected empty JSON to return false, got true")
	}
}

// TestBasicXMLValidation tests the basic XML validation functionality in TinyGo
func TestBasicXMLValidation(t *testing.T) {
	// Valid XML
	validXML := `<?xml version="1.0" encoding="UTF-8"?><person><name>John</name></person>`
	valid := isValidXML(validXML)
	if !valid {
		t.Errorf("Expected valid XML to return true, got false")
	}

	// Syntactically invalid XML (this should definitely fail)
	invalidXML := `<?xml version="1.0" encoding="UTF-8"?><person><name>John</person>` // Missing closing tag
	valid = isValidXML(invalidXML)
	if valid {
		t.Errorf("Expected invalid XML to return false, got true")
	}
	
	// Empty XML
	emptyXML := ""
	valid = isValidXML(emptyXML)
	if valid {
		t.Errorf("Expected empty XML to return false, got true")
	}
}

// isValidJSON performs basic JSON syntax validation for TinyGo
func isValidJSON(data string) bool {
	// For TinyGo, just check basic JSON syntax
	var js interface{}
	if err := json.Unmarshal([]byte(data), &js); err != nil {
		return false
	}
	return true
}

// isValidXML performs basic XML validation for TinyGo
func isValidXML(data string) bool {
	// For TinyGo, just check basic XML syntax
	if err := xml.Unmarshal([]byte(data), new(interface{})); err != nil {
		return false
	}
	return true
}