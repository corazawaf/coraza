// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
//go:build !tinygo
// +build !tinygo

package operators

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestValidateSchemaJSONBasic(t *testing.T) {
	// Create a temporary schema file
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.json")

	// Simple JSON schema for testing
	schemaContent := `{
		"type": "object",
		"properties": {
			"name": { "type": "string" },
			"age": { "type": "number" }
		},
		"required": ["name", "age"]
	}`
	err := os.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Enable to debug schema validation directly
	validateOp, ok := op.(*validateSchema)
	if !ok {
		t.Fatalf("Failed to cast operator to validateSchema")
	}

	if validateOp.jsonSchema == nil {
		t.Fatalf("JSON Schema is nil after initialization")
	}

	// Valid JSON should return false (no violation)
	validJSON := `{"name": "John", "age": 30}`

	// Validate directly
	valid := validateOp.isValidJSON(validJSON)
	if !valid {
		// Print schema and input for debugging
		t.Logf("Schema: %s", string(validateOp.schemaData))
		t.Logf("Input: %s", validJSON)
		t.Fatalf("Direct schema validation failed")
	}

	if !valid {
		t.Fatalf("JSON validation failed but should have passed")
	}

	opResult := op.Evaluate(nil, validJSON)
	if opResult {
		t.Errorf("Expected valid JSON to return false, got true - JSON validation result was: %v", valid)
	}

	// Invalid JSON syntax should return true (violation detected)
	invalidJSON := `{"name": "John", age: 30}` // Missing quotes around age
	if !op.Evaluate(nil, invalidJSON) {
		t.Errorf("Expected invalid JSON to return true, got false")
	}

	// Missing required field should return true (violation detected)
	missingFieldJSON := `{"name": "John"}` // Missing age field
	valid = validateOp.isValidJSON(missingFieldJSON)
	if valid {
		t.Fatalf("JSON validation passed but should have failed due to missing required field")
	}

	opResult = op.Evaluate(nil, missingFieldJSON)
	if !opResult {
		t.Errorf("Expected JSON with missing required field to return true, got false")
	}
}

func TestValidateSchemaJSONViaFS(t *testing.T) {
	// Simple JSON schema for testing
	schemaContent := `{
		"type": "object",
		"properties": {
			"name": { "type": "string" },
			"age": { "type": "number" }
		},
		"required": ["name", "age"]
	}`

	// Create a virtual file system
	fs := fstest.MapFS{
		"schema.json": &fstest.MapFile{
			Data: []byte(schemaContent),
		},
	}

	opts := plugintypes.OperatorOptions{
		Arguments: "schema.json",
		Root:      fs,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator via FS: %v", err)
	}

	// Valid JSON should return false (no violation)
	validJSON := `{"name": "John", "age": 30}`
	opResult := op.Evaluate(nil, validJSON)
	if opResult {
		t.Errorf("Expected valid JSON to return false, got true")
	}

	// Invalid JSON should return true (violation detected)
	invalidJSON := `{"name": "John", age: 30}` // Missing quotes around age
	if !op.Evaluate(nil, invalidJSON) {
		t.Errorf("Expected invalid JSON to return true, got false")
	}
}

func TestValidateSchemaInvalidFile(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "nonexistent.json",
	}
	_, err := NewValidateSchema(opts)
	if err == nil {
		t.Errorf("Expected error for nonexistent file, got nil")
	}
}

func TestValidateSchemaUnsupportedType(t *testing.T) {
	// Create a temporary file with unsupported extension
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.txt")
	err := os.WriteFile(schemaPath, []byte("some content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	_, err = NewValidateSchema(opts)
	if err == nil {
		t.Errorf("Expected error for unsupported schema type, got nil")
	}
}

func TestValidateSchemaEmptyInput(t *testing.T) {
	// Create a temporary schema file
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.json")

	schemaContent := `{
		"type": "object",
		"properties": {
			"name": { "type": "string" }
		},
		"required": ["name"]
	}`
	err := os.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Empty input should return false (no violation, as per original behavior)
	emptyInput := ""
	if op.Evaluate(nil, emptyInput) {
		t.Errorf("Expected empty input to return false, got true")
	}
}

// TestValidateSchemaWithRequestBody tests that the operator can validate JSON data from the REQUEST_BODY variable
func TestValidateSchemaWithRequestBody(t *testing.T) {
	// Create a temporary schema file
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.json")

	// Simple JSON schema for testing
	schemaContent := `{
		"type": "object",
		"properties": {
			"name": { "type": "string" },
			"age": { "type": "number" }
		},
		"required": ["name", "age"]
	}`
	err := os.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Create a mock TX map
	txMap := collections.NewMap(variables.TX)

	// Create a mock transaction
	tx := &mockTransaction{
		txVar: txMap,
	}

	// Set valid JSON content
	validJSON := `{"name": "John", "age": 30}`
	txMap.Set("json_request_body", []string{validJSON})

	// Valid JSON should return false (no violation)
	opResult := op.Evaluate(tx, "")
	if opResult {
		t.Errorf("Expected valid JSON to return false, got true")
	}

	// Set invalid JSON that's missing a required field
	invalidJSON := `{"name": "John"}`
	txMap.Set("json_request_body", []string{invalidJSON})

	// Invalid JSON should return true (violation detected)
	opResult = op.Evaluate(tx, "")
	if !opResult {
		t.Errorf("Expected invalid JSON to return true, got false")
	}
}

// TestValidateSchemaWithResponseBody tests that the operator can validate JSON data from the RESPONSE_BODY variable
func TestValidateSchemaWithResponseBody(t *testing.T) {
	// Create a temporary schema file
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.json")

	// Simple JSON schema for testing
	schemaContent := `{
		"type": "object",
		"properties": {
			"name": { "type": "string" },
			"age": { "type": "number" }
		},
		"required": ["name", "age"]
	}`
	err := os.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Create a mock TX map
	txMap := collections.NewMap(variables.TX)

	// Create a mock transaction
	tx := &mockTransaction{
		txVar: txMap,
	}

	// Set valid JSON content
	validJSON := `{"name": "John", "age": 30}`
	txMap.Set("json_response_body", []string{validJSON})

	// Valid JSON should return false (no violation)
	opResult := op.Evaluate(tx, "")
	if opResult {
		t.Errorf("Expected valid JSON to return false, got true")
	}

	// Set invalid JSON that's missing a required field
	invalidJSON := `{"name": "John"}`
	txMap.Set("json_response_body", []string{invalidJSON})

	// Invalid JSON should return true (violation detected)
	opResult = op.Evaluate(tx, "")
	if !opResult {
		t.Errorf("Expected invalid JSON to return true, got false")
	}
}

func TestValidateSchemaWithNoArguments(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "",
	}
	_, err := NewValidateSchema(opts)
	if err == nil {
		t.Errorf("Expected error for empty schema path, got nil")
	}
}

// TestValidateSchemaInvalidJSONSchema tests with an invalid JSON schema
func TestValidateSchemaInvalidJSONSchema(t *testing.T) {
	// Create a temporary schema file with invalid JSON
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.json")

	// Invalid JSON schema
	schemaContent := `{
		"type": "object",
		"properties": {
			"name": { "type": "string" },
			"age": { "type": "number"
		},
		"required": ["name", "age"]
	}` // Missing closing bracket
	err := os.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	_, err = NewValidateSchema(opts)
	if err == nil {
		t.Errorf("Expected error for invalid JSON schema, got nil")
	}
}

// TestValidateSchemaJSONNilSchema tests evaluation with a nil schema validator
func TestValidateSchemaJSONNilSchema(t *testing.T) {
	// Create a temporary schema file
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.json")

	// Simple JSON schema for testing (we won't actually use the schema's contents)
	schemaContent := `{
		"type": "object",
		"properties": {
			"name": { "type": "string" }
		}
	}`
	err := os.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Cast to validateSchema to manipulate the internals
	validateOp, ok := op.(*validateSchema)
	if !ok {
		t.Fatalf("Failed to cast operator to validateSchema")
	}

	validateOp.jsonSchema = nil

	// Valid JSON syntax but nil schema should just do basic JSON validation
	validJSON := `{"name": "John"}`
	result := validateOp.isValidJSON(validJSON)
	if !result {
		t.Errorf("Expected valid JSON to return true even with nil schema, got false")
	}
}

// Mock transaction for testing
type mockTransaction struct {
	txVar *collections.Map
}

func (m *mockTransaction) ID() string {
	return "mock-tx"
}

func (m *mockTransaction) Variables() plugintypes.TransactionVariables {
	return m
}

func (m *mockTransaction) Collection(idx variables.RuleVariable) collection.Collection {
	switch idx {
	case variables.TX:
		return m.txVar
	default:
		return nil
	}
}

func (m *mockTransaction) Interrupt(i *types.Interruption) {}

func (m *mockTransaction) DebugLogger() debuglog.Logger {
	return debuglog.Noop()
}

func (m *mockTransaction) Capturing() bool {
	return false
}

func (m *mockTransaction) CaptureField(idx int, value string) {}

func (m *mockTransaction) LastPhase() types.RulePhase {
	return types.PhaseRequestHeaders
}

// Implement TransactionVariables interface
func (m *mockTransaction) All(f func(v variables.RuleVariable, col collection.Collection) bool) {
	f(variables.TX, m.txVar)
}

func (m *mockTransaction) TX() collection.Map {
	return m.txVar
}

func (m *mockTransaction) RequestXML() collection.Map {
	return nil
}

func (m *mockTransaction) XML() collection.Map {
	return nil
}

// Other interface methods that we don't need for our tests
func (m *mockTransaction) UrlencodedError() collection.Single              { return nil }
func (m *mockTransaction) ResponseContentType() collection.Single          { return nil }
func (m *mockTransaction) UniqueID() collection.Single                     { return nil }
func (m *mockTransaction) ArgsCombinedSize() collection.Collection         { return nil }
func (m *mockTransaction) FilesCombinedSize() collection.Single            { return nil }
func (m *mockTransaction) FullRequestLength() collection.Single            { return nil }
func (m *mockTransaction) InboundDataError() collection.Single             { return nil }
func (m *mockTransaction) MatchedVar() collection.Single                   { return nil }
func (m *mockTransaction) MatchedVarName() collection.Single               { return nil }
func (m *mockTransaction) MultipartDataAfter() collection.Single           { return nil }
func (m *mockTransaction) MultipartPartHeaders() collection.Map            { return nil }
func (m *mockTransaction) OutboundDataError() collection.Single            { return nil }
func (m *mockTransaction) QueryString() collection.Single                  { return nil }
func (m *mockTransaction) RemoteAddr() collection.Single                   { return nil }
func (m *mockTransaction) RemoteHost() collection.Single                   { return nil }
func (m *mockTransaction) RemotePort() collection.Single                   { return nil }
func (m *mockTransaction) RequestBodyError() collection.Single             { return nil }
func (m *mockTransaction) RequestBodyErrorMsg() collection.Single          { return nil }
func (m *mockTransaction) RequestBodyProcessorError() collection.Single    { return nil }
func (m *mockTransaction) RequestBodyProcessorErrorMsg() collection.Single { return nil }
func (m *mockTransaction) RequestBodyProcessor() collection.Single         { return nil }
func (m *mockTransaction) RequestBasename() collection.Single              { return nil }
func (m *mockTransaction) RequestBody() collection.Single                  { return nil }
func (m *mockTransaction) RequestBodyLength() collection.Single            { return nil }
func (m *mockTransaction) RequestFilename() collection.Single              { return nil }
func (m *mockTransaction) Args() collection.Keyed                          { return nil }
func (m *mockTransaction) ArgsGet() collection.Map                         { return nil }
func (m *mockTransaction) ArgsPost() collection.Map                        { return nil }
func (m *mockTransaction) ArgsPath() collection.Map                        { return nil }
func (m *mockTransaction) ArgsNames() collection.Keyed                     { return nil }
func (m *mockTransaction) ArgsGetNames() collection.Keyed                  { return nil }
func (m *mockTransaction) ArgsPostNames() collection.Keyed                 { return nil }
func (m *mockTransaction) Duration() collection.Single                     { return nil }
func (m *mockTransaction) Files() collection.Map                           { return nil }
func (m *mockTransaction) FilesNames() collection.Map                      { return nil }
func (m *mockTransaction) FilesSizes() collection.Map                      { return nil }
func (m *mockTransaction) FilesTmpNames() collection.Map                   { return nil }
func (m *mockTransaction) FilesTmpContent() collection.Map                 { return nil }
func (m *mockTransaction) Env() collection.Map                             { return nil }
func (m *mockTransaction) Rule() collection.Map                            { return nil }
func (m *mockTransaction) RequestHeaders() collection.Map                  { return nil }
func (m *mockTransaction) RequestHeadersNames() collection.Keyed           { return nil }
func (m *mockTransaction) RequestCookies() collection.Map                  { return nil }
func (m *mockTransaction) RequestCookiesNames() collection.Keyed           { return nil }
func (m *mockTransaction) ResponseHeaders() collection.Map                 { return nil }
func (m *mockTransaction) ResponseHeadersNames() collection.Keyed          { return nil }
func (m *mockTransaction) Geo() collection.Map                             { return nil }
func (m *mockTransaction) MatchedVars() collection.Map                     { return nil }
func (m *mockTransaction) MatchedVarsNames() collection.Keyed              { return nil }
func (m *mockTransaction) MultipartName() collection.Map                   { return nil }
func (m *mockTransaction) MultipartFilename() collection.Map               { return nil }
func (m *mockTransaction) MultipartStrictError() collection.Single         { return nil }
func (m *mockTransaction) HighestSeverity() collection.Single              { return nil }
func (m *mockTransaction) StatusLine() collection.Single                   { return nil }
func (m *mockTransaction) ResponseStatus() collection.Single               { return nil }
func (m *mockTransaction) ResponseBody() collection.Single                 { return nil }
func (m *mockTransaction) ResponseBodyLength() collection.Single           { return nil }
func (m *mockTransaction) ResponseProtocol() collection.Single             { return nil }
func (m *mockTransaction) ResponseContentLength() collection.Single        { return nil }
func (m *mockTransaction) ResponseBodyProcessor() collection.Single        { return nil }
func (m *mockTransaction) ServerAddr() collection.Single                   { return nil }
func (m *mockTransaction) ServerName() collection.Single                   { return nil }
func (m *mockTransaction) ServerPort() collection.Single                   { return nil }
func (m *mockTransaction) RequestLine() collection.Single                  { return nil }
func (m *mockTransaction) RequestURI() collection.Single                   { return nil }
func (m *mockTransaction) RequestURIRaw() collection.Single                { return nil }
func (m *mockTransaction) RequestMethod() collection.Single                { return nil }
func (m *mockTransaction) RequestProtocol() collection.Single              { return nil }
func (m *mockTransaction) ResponseArgs() collection.Map                    { return nil }
func (m *mockTransaction) ResponseXML() collection.Map                     { return nil }

// TestValidateSchemaWithEmptyData tests evaluation with empty data
func TestValidateSchemaWithEmptyData(t *testing.T) {
	// Create a temporary schema file
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.json")

	schemaContent := `{
		"type": "object",
		"properties": {
			"name": { "type": "string" }
		}
	}`
	err := os.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Test with empty data should return false (no violation)
	if op.Evaluate(nil, "") {
		t.Errorf("Expected empty data to return false, got true")
	}
}

// TestValidateSchemaWithCompilerError tests JSON schema compiler error
func TestValidateSchemaWithCompilerError(t *testing.T) {
	// Create a temporary schema file with invalid schema format
	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "schema.json")

	// This is valid JSON but not a valid JSON schema
	schemaContent := `{
		"type": "invalid-type-value",
		"properties": 123
	}`

	err := os.WriteFile(schemaPath, []byte(schemaContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test schema file: %v", err)
	}

	opts := plugintypes.OperatorOptions{
		Arguments: schemaPath,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		// If the schema library rejects this at creation time, that's acceptable
		return
	}

	// Force initialization - this should fail during schema compilation
	validateOp, ok := op.(*validateSchema)
	if !ok {
		t.Fatalf("Failed to cast operator to validateSchema")
	}

	// Either we should get an error or the jsonSchema should be nil
	if err == nil && validateOp.jsonSchema != nil {
		jsonData := `{"test": "value"}`
		// Try validation - should handle errors gracefully
		result := validateOp.isValidJSON(jsonData)
		// We're just testing that it doesn't panic here
		t.Logf("Validation result with bad schema compiler: %v", result)
	}
}

// TestValidateSchemaWithFSRootError tests error path with invalid FS
func TestValidateSchemaWithFSRootError(t *testing.T) {
	// Create a fake filesystem that will generate an error
	fs := fstest.MapFS{}

	opts := plugintypes.OperatorOptions{
		Arguments: "nonexistent.json",
		Root:      fs,
	}

	_, err := NewValidateSchema(opts)
	if err == nil {
		t.Errorf("Expected error for nonexistent file in FS, got nil")
	}
}
