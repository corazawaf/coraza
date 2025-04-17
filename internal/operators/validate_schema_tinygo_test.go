// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package operators

import (
	"encoding/json"
	"fmt"
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
	// Create temporary directories for test files
	validTempDir := t.TempDir()
	
	// Create a valid JSON schema file
	validSchemaContent := `{"type": "object", "properties": {"name":{"type":"string"}}}`
	validSchemaPath := createTempSchemaFile(t, validTempDir, "valid_schema", validSchemaContent, ".json")

	// Create a valid operator
	op, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: validSchemaPath})
	if err != nil {
		t.Fatalf("Failed to create operator: %v", err)
	}
	
	// Test the initValidators method
	validateOp, ok := op.(*validateSchema)
	if !ok {
		t.Fatalf("Failed to cast to validateSchema")
	}
	
	// Test initialization - should succeed
	err = validateOp.initValidators()
	if err != nil {
		t.Errorf("Expected no error from initValidators, got: %v", err)
	}
	
	// Test with error condition
	validateOp.initError = fmt.Errorf("test error")
	res := validateOp.Evaluate(nil, `{"name":"John"}`)
	if res {
		t.Errorf("Expected false when initError is set, got true")
	}
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


// isValidJSON performs basic JSON syntax validation for TinyGo
func isValidJSON(data string) bool {
	// For TinyGo, just check basic JSON syntax
	var js interface{}
	if err := json.Unmarshal([]byte(data), &js); err != nil {
		return false
	}
	return true
}

