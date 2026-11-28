//go:build !tinygo

// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package operators

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func setupJSONSchema(name, data string) fs.FS {
	return fstest.MapFS{
		name: &fstest.MapFile{
			Data: []byte(data),
			Mode: 0644,
		},
	}
}

func TestValidateSchemaJSONBasic(t *testing.T) {
	schema := "schema.json"
	rootFS := setupJSONSchema(schema, `{
		"type": "object",
		"properties": {
			"name": { "type": "string" },
			"age": { "type": "number" }
		},
		"required": ["name", "age"]
	}`)

	opts := plugintypes.OperatorOptions{
		Arguments: schema,
		Root:      rootFS,
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

	// Trailing tokens after valid JSON should return true (violation detected)
	trailingJSON := `{"name": "John", "age": 30} trailing`
	if !op.Evaluate(nil, trailingJSON) {
		t.Errorf("Expected JSON with trailing tokens to return true, got false")
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

func TestValidateSchemaInvalidFile(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "nonexistent.json",
		Root:      fstest.MapFS{},
	}
	_, err := NewValidateSchema(opts)
	if err == nil {
		t.Errorf("Expected error for nonexistent file, got nil")
	}
}

func TestValidateSchemaUnsupportedType(t *testing.T) {
	// Create a temporary file with unsupported extension
	var (
		name   = "schema.xml"
		rootFS = setupJSONSchema(name, "")
	)

	opts := plugintypes.OperatorOptions{
		Arguments: name,
		Root:      rootFS,
	}
	_, err := NewValidateSchema(opts)
	if err == nil {
		t.Errorf("Expected error for unsupported schema type, got nil")
	}
}

func TestValidateSchemaEmptyInput(t *testing.T) {
	var (
		name   = "schema.json"
		rootFS = setupJSONSchema(name, `{
		"type": "object",
		"properties": {
			"name": { "type": "string" }
		},
		"required": ["name"]
	}`)
	)

	opts := plugintypes.OperatorOptions{
		Arguments: name,
		Root:      rootFS,
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
	var (
		name   = "schema.json"
		rootFS = setupJSONSchema(name, `{
			"type": "object",
			"properties": {
				"name": { "type": "string" },
				"age": { "type": "number" }
			},
			"required": ["name", "age"]
		}`)
	)

	opts := plugintypes.OperatorOptions{
		Arguments: name,
		Root:      rootFS,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Create a mock TX map
	txMap := collections.NewMap(variables.TX)

	// Create a mock transaction in the request body phase
	tx := &mockTransaction{
		txVar:     txMap,
		lastPhase: types.PhaseRequestBody,
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
	var (
		name   = "schema.json"
		rootFS = setupJSONSchema(name, `{
			"type": "object",
			"properties": {
				"name": { "type": "string" },
				"age": { "type": "number" }
			},
			"required": ["name", "age"]
		}`)
	)

	opts := plugintypes.OperatorOptions{
		Arguments: name,
		Root:      rootFS,
	}
	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Create a mock TX map
	txMap := collections.NewMap(variables.TX)

	// Create a mock transaction in the response body phase
	tx := &mockTransaction{
		txVar:     txMap,
		lastPhase: types.PhaseResponseBody,
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
	var (
		name   = "schema.json"
		rootFS = setupJSONSchema(name, `{
			"type": "object",
			"properties": {
				"name": { "type": "string" },
				"age": { "type": "number" -> here it is the error
			},
			"required": ["name", "age"]
		}`)
	)

	opts := plugintypes.OperatorOptions{
		Arguments: name,
		Root:      rootFS,
	}
	_, err := NewValidateSchema(opts)
	if err == nil {
		t.Errorf("Expected error for invalid JSON schema, got nil")
	}
}

// TestValidateSchemaJSONNilSchema tests evaluation with a nil schema validator
func TestValidateSchemaJSONNilSchema(t *testing.T) {
	var (
		name   = "schema.json"
		rootFS = setupJSONSchema(name, `{
			"type": "object",
			"properties": {
				"name": { "type": "string" }
			}
		}`)
	)

	opts := plugintypes.OperatorOptions{
		Arguments: name,
		Root:      rootFS,
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
	txVar     *collections.Map
	lastPhase types.RulePhase
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
	return m.lastPhase
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
func (m *mockTransaction) MultipartFilenameCharset() collection.Map        { return nil }
func (m *mockTransaction) MultipartFilenameLanguage() collection.Map       { return nil }
func (m *mockTransaction) MultipartStrictError() collection.Single         { return nil }
func (m *mockTransaction) MultipartDuplicatePartHeader() collection.Single { return nil }
func (m *mockTransaction) MultipartInvalidQuoting() collection.Single      { return nil }
func (m *mockTransaction) ArgumentsLimitReached() collection.Single        { return nil }
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

// TestValidateSchemaPhaseChecking tests that the operator respects phases for request/response body validation
func TestValidateSchemaPhaseChecking(t *testing.T) {
	var (
		name   = "schema.json"
		rootFS = setupJSONSchema(name, `{
			"type": "object",
			"properties": {
				"name": { "type": "string" }
			},
			"required": ["name"]
		}`)
	)

	opts := plugintypes.OperatorOptions{
		Arguments: name,
		Root:      rootFS,
	}

	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Create a mock TX map
	txMap := collections.NewMap(variables.TX)

	// Test: Request body data should not be validated in PhaseRequestHeaders (phase 1)
	tx := &mockTransaction{
		txVar:     txMap,
		lastPhase: types.PhaseRequestHeaders,
	}

	// Set invalid JSON that would normally fail validation
	invalidJSON := `{"invalid": "missing required name field"}`
	txMap.Set("json_request_body", []string{invalidJSON})

	// Should return false (no violation) because we're not in the right phase
	opResult := op.Evaluate(tx, "")
	if opResult {
		t.Errorf("Expected request body validation to be skipped in phase 1, but got violation")
	}

	// Test: Request body data should be validated in PhaseRequestBody (phase 2)
	tx.lastPhase = types.PhaseRequestBody
	opResult = op.Evaluate(tx, "")
	if !opResult {
		t.Errorf("Expected request body validation to trigger violation in phase 2, got false")
	}

	// Clear request body data and test response body
	txMap.Remove("json_request_body")

	// Test: Response body data should not be validated in PhaseResponseHeaders (phase 3)
	tx.lastPhase = types.PhaseResponseHeaders
	txMap.Set("json_response_body", []string{invalidJSON})

	opResult = op.Evaluate(tx, "")
	if opResult {
		t.Errorf("Expected response body validation to be skipped in phase 3, but got violation")
	}

	// Test: Response body data should be validated in PhaseResponseBody (phase 4)
	tx.lastPhase = types.PhaseResponseBody
	opResult = op.Evaluate(tx, "")
	if !opResult {
		t.Errorf("Expected response body validation to trigger violation in phase 4, got false")
	}

	// Test: Response body data should also be validated in PhaseLogging (phase 5)
	tx.lastPhase = types.PhaseLogging
	opResult = op.Evaluate(tx, "")
	if !opResult {
		t.Errorf("Expected response body validation to trigger violation in phase 5, got false")
	}
}

// TestValidateSchemaPhasePreference tests that request body is preferred over response body in the right phases
func TestValidateSchemaPhasePreference(t *testing.T) {
	var (
		name   = "schema.json"
		rootFS = setupJSONSchema(name, `{
			"type": "object",
			"properties": {
				"name": { "type": "string" }
			},
			"required": ["name"]
		}`)
	)

	opts := plugintypes.OperatorOptions{
		Arguments: name,
		Root:      rootFS,
	}

	op, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize validateSchema operator: %v", err)
	}

	// Create a mock TX map
	txMap := collections.NewMap(variables.TX)

	// Set both request and response body data
	validRequestJSON := `{"name": "John"}` // Valid for request
	invalidResponseJSON := `{"age": 30}`   // Invalid (missing name)

	txMap.Set("json_request_body", []string{validRequestJSON})
	txMap.Set("json_response_body", []string{invalidResponseJSON})

	// Test: In phase 2, should prefer request body over response body
	tx := &mockTransaction{
		txVar:     txMap,
		lastPhase: types.PhaseRequestBody,
	}

	opResult := op.Evaluate(tx, "")
	if opResult {
		t.Errorf("Expected request body to be validated (valid) in phase 2, but got violation")
	}

	// Test: In phase 4, should prefer response body over request body
	tx.lastPhase = types.PhaseResponseBody
	opResult = op.Evaluate(tx, "")
	if !opResult {
		t.Errorf("Expected response body to be preferred in phase 4, but got no violation (should have failed on invalid response body)")
	}

	// Test: In phase 4 with only response body, should validate response body
	txMap.Remove("json_request_body")
	opResult = op.Evaluate(tx, "")
	if !opResult {
		t.Errorf("Expected response body validation to trigger violation when only response body is available")
	}
}

func TestMemoizeKey(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		same bool
	}{
		{"same operator and content", memoizeKey("validateSchema", "x"), memoizeKey("validateSchema", "x"), true},
		{"different content", memoizeKey("validateSchema", "x"), memoizeKey("validateSchema", "y"), false},
		{"different operator", memoizeKey("validateSchema", "x"), memoizeKey("pm", "x"), false},
		{"content split differently", memoizeKey("validateSchema", "ab"), memoizeKey("validateSchema", "a", "b"), false},
		{"NUL inside an element", memoizeKey("validateSchema", "a\x00b"), memoizeKey("validateSchema", "a", "b"), false},
		{"empty element is not nothing", memoizeKey("validateSchema", "a", ""), memoizeKey("validateSchema", "a"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if (tc.a == tc.b) != tc.same {
				t.Errorf("keys equal = %v, want %v (%q vs %q)", tc.a == tc.b, tc.same, tc.a, tc.b)
			}
		})
	}
	if key := memoizeKey("validateSchema", "x"); !strings.HasPrefix(key, "validateSchema:") {
		t.Errorf("key must be namespaced by operator, got %q", key)
	}
}

func TestValidateSchemaDraft07AndRefs(t *testing.T) {
	schema := "schema.json"
	rootFS := setupJSONSchema(schema, `{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"definitions": {
			"item": {
				"type": "object",
				"properties": {
					"id": { "type": "integer", "minimum": 1 },
					"tag": { "type": "string", "minLength": 2 }
				},
				"required": ["id", "tag"]
			}
		},
		"properties": {
			"items": {
				"type": "array",
				"items": { "$ref": "#/definitions/item" },
				"minItems": 1
			}
		},
		"required": ["items"]
	}`)

	op, err := NewValidateSchema(plugintypes.OperatorOptions{
		Arguments: schema,
		Root:      rootFS,
	})
	if err != nil {
		t.Fatalf("Failed to initialize draft-07 schema operator: %v", err)
	}

	if op.Evaluate(nil, `{"items":[{"id":1,"tag":"ok"}]}`) {
		t.Errorf("Expected valid draft-07 payload with local $ref to return false")
	}
	if !op.Evaluate(nil, `{"items":[{"id":0,"tag":"ok"}]}`) {
		t.Errorf("Expected minimum constraint violation to return true")
	}
	if !op.Evaluate(nil, `{"items":[{"id":1,"tag":"x"}]}`) {
		t.Errorf("Expected minLength constraint violation to return true")
	}
	if !op.Evaluate(nil, `{"items":[]} `) {
		t.Errorf("Expected minItems constraint violation to return true")
	}
	if !op.Evaluate(nil, `null`) {
		t.Errorf("Expected non-object JSON null to return true")
	}
}

func TestValidateSchemaAdvancedAndConcurrency(t *testing.T) {
	schema := "schema.json"
	rootFS := setupJSONSchema(schema, `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$defs": {
			"role": {
				"oneOf": [
					{ "const": "viewer" },
					{ "type": "object", "properties": { "admin": { "type": "boolean" } }, "required": ["admin"], "additionalProperties": false }
				]
			}
		},
		"type": "object",
		"properties": {
			"count": { "type": "integer", "minimum": 0, "maximum": 9007199254740993 },
			"code": { "type": "string", "pattern": "^[A-Z]{2}-[0-9]{3}$" },
			"role": { "$ref": "#/$defs/role" }
		},
		"required": ["count", "code", "role"],
		"additionalProperties": false
	}`)

	memo := &testMemoizer{entries: make(map[string]any)}
	opts := plugintypes.OperatorOptions{
		Arguments: schema,
		Root:      rootFS,
		Memoizer:  memo,
	}

	op1, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize schema operator: %v", err)
	}
	op2, err := NewValidateSchema(opts)
	if err != nil {
		t.Fatalf("Failed to initialize memoized schema operator: %v", err)
	}
	if op1.(*validateSchema).jsonSchema != op2.(*validateSchema).jsonSchema {
		t.Fatalf("Expected memoizer to reuse compiled schema instance")
	}

	cases := []struct {
		name      string
		payload   string
		violation bool
	}{
		{"valid payload with exact large int64", `{"count":9007199254740993,"code":"US-123","role":{"admin":true}}`, false},
		{"valid string const oneOf", `{"count":0,"code":"CA-999","role":"viewer"}`, false},
		{"integer represented with .0 is integer", `{"count":5.0,"code":"US-123","role":"viewer"}`, false},
		{"fractional float fails integer check", `{"count":5.5,"code":"US-123","role":"viewer"}`, true},
		{"exceeds int64 maximum", `{"count":9007199254740994,"code":"US-123","role":"viewer"}`, true},
		{"regex mismatch", `{"count":1,"code":"us-123","role":"viewer"}`, true},
		{"unexpected property blocked", `{"count":1,"code":"US-123","role":"viewer","extra":1}`, true},
		{"invalid oneOf extra key", `{"count":1,"code":"US-123","role":{"admin":true,"x":2}}`, true},
		{"whitespace-only JSON violates", `   `, true},
		{"NUL byte inside JSON string rejected", "{\"count\":1,\"code\":\"US-123\",\"role\":\"viewer\x00\"}", true},
		{"trailing valid JSON object rejected", `{"count":1,"code":"US-123","role":"viewer"}{"count":2}`, true},
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, tc := range cases {
				got := op1.Evaluate(nil, tc.payload)
				if got != tc.violation {
					t.Errorf("%s: Evaluate() = %v, want %v (payload=%q)", tc.name, got, tc.violation, tc.payload)
				}
			}
		}()
	}
	wg.Wait()
}

type testMemoizer struct {
	mu      sync.Mutex
	entries map[string]any
}

func (m *testMemoizer) Do(key string, fn func() (any, error)) (any, error) {
	m.mu.Lock()
	if v, ok := m.entries[key]; ok {
		m.mu.Unlock()
		return v, nil
	}
	m.mu.Unlock()
	v, err := fn()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.entries[key] = v
	m.mu.Unlock()
	return v, nil
}

func TestValidateSchemaBooleanAndInvalidRegexSchema(t *testing.T) {
	if _, err := NewValidateSchema(plugintypes.OperatorOptions{
		Arguments: "bad.json",
		Root:      setupJSONSchema("bad.json", `{"type":"string","pattern":"["}`),
	}); err == nil {
		t.Fatalf("Expected invalid regex pattern in schema to return compile error")
	}

	if op, err := NewValidateSchema(plugintypes.OperatorOptions{
		Arguments: "true.json",
		Root:      setupJSONSchema("true.json", `true`),
	}); err != nil {
		t.Fatalf("Expected boolean schema true to compile: %v", err)
	} else if op.Evaluate(nil, `{"anything":123}`) {
		t.Errorf("Expected boolean true schema to accept valid JSON object")
	}

	if op, err := NewValidateSchema(plugintypes.OperatorOptions{
		Arguments: "false.json",
		Root:      setupJSONSchema("false.json", `false`),
	}); err != nil {
		t.Fatalf("Expected boolean schema false to compile: %v", err)
	} else if !op.Evaluate(nil, `{"anything":123}`) {
		t.Errorf("Expected boolean false schema to reject valid JSON object")
	}
}

func TestValidateSchemaSecurityAndCompat(t *testing.T) {
	t.Run("contentEncoding base64 and contentSchema enforced safely", func(t *testing.T) {
		op, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "schema.json",
			Root:      setupJSONSchema("schema.json", `{"type":"string","contentEncoding":"base64"}`),
		})
		if err != nil {
			t.Fatalf("compile contentEncoding schema: %v", err)
		}
		if op.Evaluate(nil, `"YQ=="`) {
			t.Errorf("expected valid base64 YQ== to pass")
		}
		if !op.Evaluate(nil, `"!!!"`) {
			t.Errorf("expected invalid base64 !!! to trigger violation")
		}

		cOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "content-schema.json",
			Root:      setupJSONSchema("content-schema.json", `{"type":"string","contentEncoding":"base64","contentMediaType":"application/json","contentSchema":{"type":"object","properties":{"n":{"type":"number","minimum":0}},"required":["n"]}}`),
		})
		if err != nil {
			t.Fatalf("compile contentSchema: %v", err)
		}
		validInner := base64.StdEncoding.EncodeToString([]byte(`{"n":42}`))
		if cOp.Evaluate(nil, fmt.Sprintf("%q", validInner)) {
			t.Errorf("expected valid base64 JSON matching contentSchema to pass")
		}
		badPosExpInner := base64.StdEncoding.EncodeToString([]byte(`{"n":1e9999999999}`))
		if !cOp.Evaluate(nil, fmt.Sprintf("%q", badPosExpInner)) {
			t.Errorf("expected smuggled base64 oversized positive exponent to trigger violation without panic")
		}
		badNegExpInner := base64.StdEncoding.EncodeToString([]byte(`{"n":1e-9999999999}`))
		if !cOp.Evaluate(nil, fmt.Sprintf("%q", badNegExpInner)) {
			t.Errorf("expected smuggled base64 oversized negative exponent to trigger violation without panic")
		}

		plainCOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "plain-content-schema.json",
			Root:      setupJSONSchema("plain-content-schema.json", `{"type":"string","contentMediaType":"application/json","contentSchema":{"type":"number","minimum":0}}`),
		})
		if err != nil {
			t.Fatalf("compile plain contentSchema: %v", err)
		}
		if plainCOp.Evaluate(nil, `"1"`) {
			t.Errorf("expected valid embedded JSON string to pass contentSchema")
		}
		if !plainCOp.Evaluate(nil, `"1e9999999999"`) || !plainCOp.Evaluate(nil, `"1e-9999999999"`) {
			t.Errorf("expected out-of-range embedded JSON numbers to trigger violation without panic")
		}
	})

	t.Run("oversized positive and negative exponents and uniqueItems reject cleanly without panic", func(t *testing.T) {
		uOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "schema.json",
			Root:      setupJSONSchema("schema.json", `{"type":"array","uniqueItems":true}`),
		})
		if err != nil {
			t.Fatalf("compile uniqueItems schema: %v", err)
		}
		for _, payload := range []string{
			`[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,1e9999999999]`,
			`[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,1e-9999999999]`,
			`[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,1e-100000]`,
		} {
			if !uOp.Evaluate(nil, payload) {
				t.Errorf("expected oversized exponent %s inside uniqueItems array to trigger violation", payload)
			}
		}

		mOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "min.json",
			Root:      setupJSONSchema("min.json", `{"type":"object","properties":{"n":{"type":"number","minimum":0}}}`),
		})
		if err != nil {
			t.Fatalf("compile minimum schema: %v", err)
		}
		for _, payload := range []string{`{"n":1e9999999999}`, `{"n":1e-9999999999}`, `{"n":1e-100000}`, `{"n":1e100000}`} {
			if !mOp.Evaluate(nil, payload) {
				t.Errorf("expected nested oversized exponent %s to trigger violation", payload)
			}
		}
		for _, badSchema := range []string{
			`{"type":"number","minimum":1e9999999999}`,
			`{"type":"number","minimum":1e-9999999999}`,
		} {
			if _, err := NewValidateSchema(plugintypes.OperatorOptions{
				Arguments: "badnum.json",
				Root:      setupJSONSchema("badnum.json", badSchema),
			}); err == nil {
				t.Errorf("expected schema with out-of-range numeric literal %s to fail compilation", badSchema)
			}
		}
	})

	t.Run("file scheme ref denied while bounded HTTP ref works and oversized remote fails", func(t *testing.T) {
		localPath := filepath.Join(t.TempDir(), "secret.json")
		if err := os.WriteFile(localPath, []byte(`{"type":"string"}`), 0o600); err != nil {
			t.Fatalf("write local fixture: %v", err)
		}
		fileURI := "file://" + filepath.ToSlash(localPath)
		if !strings.HasPrefix(fileURI, "file:///") {
			fileURI = "file:///" + strings.TrimPrefix(filepath.ToSlash(localPath), "/")
		}
		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "file.json",
			Root:      setupJSONSchema("file.json", fmt.Sprintf(`{"$ref":%q}`, fileURI)),
		}); err == nil {
			t.Errorf("expected file:// $ref to fail closed")
		} else if !strings.Contains(err.Error(), "no URLLoader registered") {
			t.Errorf("expected unsupported file:// scheme error, got: %v", err)
		}

		smallSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if _, err := io.WriteString(w, `{"type":"integer","minimum":1}`); err != nil {
				t.Errorf("write HTTP schema fixture: %v", err)
			}
		}))
		defer smallSrv.Close()

		op, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "http.json",
			Root:      setupJSONSchema("http.json", fmt.Sprintf(`{"$ref":%q}`, smallSrv.URL+"/item.json")),
		})
		if err != nil {
			t.Fatalf("compile schema with small HTTP $ref: %v", err)
		}
		if op.Evaluate(nil, `42`) || !op.Evaluate(nil, `0`) || !op.Evaluate(nil, `"42"`) {
			t.Errorf("HTTP $ref schema validation mismatch")
		}

		bigSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"type":"string","description":"` + strings.Repeat("a", maxRemoteSchemaBytes+16) + `"}`))
		}))
		defer bigSrv.Close()

		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "big.json",
			Root:      setupJSONSchema("big.json", fmt.Sprintf(`{"$ref":%q}`, bigSrv.URL+"/big.json")),
		}); err == nil {
			t.Errorf("expected oversized remote HTTP schema response to be rejected")
		} else if !strings.Contains(err.Error(), "byte limit") {
			t.Errorf("expected remote size limit error, got: %v", err)
		}

		// http -> https -> http downgrade must be blocked on the latest hop.
		downgradeRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			var location string
			switch req.URL.String() {
			case "http://schema.example/start.json":
				location = "https://schema.example/upgraded.json"
			case "https://schema.example/upgraded.json":
				location = "http://schema.example/downgraded.json"
			default:
				return nil, fmt.Errorf("unexpected request URL: %s", req.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{location}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		})
		if _, err := newValidateSchema(plugintypes.OperatorOptions{
			Arguments: "downgrade.json",
			Root:      setupJSONSchema("downgrade.json", `{"$ref":"http://schema.example/start.json"}`),
		}, downgradeRT); err == nil {
			t.Errorf("expected http -> https -> http redirect downgrade to fail")
		} else if !strings.Contains(err.Error(), "refusing HTTPS-to-HTTP redirect") {
			t.Errorf("expected HTTPS-to-HTTP redirect refusal error, got: %v", err)
		}
	})

	t.Run("application/xml enforced, unsupported yaml or contentEncoding and draft-07 contentSchema fail closed, minContains without contains allowed", func(t *testing.T) {
		xmlOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "xml.json",
			Root:      setupJSONSchema("xml.json", `{"type":"string","contentMediaType":"application/xml"}`),
		})
		if err != nil {
			t.Fatalf("compile application/xml schema: %v", err)
		}
		if xmlOp.Evaluate(nil, `"<a>1</a>"`) {
			t.Errorf("expected valid XML payload to pass")
		}
		if !xmlOp.Evaluate(nil, `"<a>"`) || !xmlOp.Evaluate(nil, `"<a></b>"`) {
			t.Errorf("expected malformed XML payload to trigger violation")
		}

		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "yaml.json",
			Root:      setupJSONSchema("yaml.json", `{"type":"string","contentMediaType":"application/yaml"}`),
		}); err == nil {
			t.Errorf("expected unsupported contentMediaType application/yaml to fail compilation")
		}

		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "enc.json",
			Root:      setupJSONSchema("enc.json", `{"type":"string","contentEncoding":"hex"}`),
		}); err == nil {
			t.Errorf("expected unsupported contentEncoding hex to fail compilation")
		} else if !strings.Contains(err.Error(), "unsupported contentEncoding") {
			t.Errorf("expected unsupported contentEncoding error, got: %v", err)
		}

		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "draft7-cs.json",
			Root:      setupJSONSchema("draft7-cs.json", `{"$schema":"http://json-schema.org/draft-07/schema#","type":"string","contentMediaType":"application/json","contentSchema":{"type":"object","required":["a"]}}`),
		}); err == nil {
			t.Errorf("expected draft-07 schema with contentSchema to fail initialization instead of silently ignoring contentSchema")
		} else if !strings.Contains(err.Error(), "contentSchema is not supported under JSON Schema draft-07") {
			t.Errorf("expected clear draft-07 contentSchema migration message, got: %v", err)
		}

		// Under default draft 2020-12, a nested subschema with empty "$id" keeps the inherited draft
		// in jsonschema/v6, so it compiles and retains contentSchema enforcement.
		if emptyIDOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "nested-empty-id-draft7.json",
			Root:      setupJSONSchema("nested-empty-id-draft7.json", `{"type":"object","properties":{"payload":{"$id":"","$schema":"http://json-schema.org/draft-07/schema#","type":"string","contentMediaType":"application/json","contentSchema":{"type":"object","required":["a"]}}}}`),
		}); err != nil {
			t.Fatalf("expected nested empty $id with draft-07 $schema and contentSchema to compile under default draft: %v", err)
		} else {
			if emptyIDOp.Evaluate(nil, `{"payload":"{\"a\":1}"}`) {
				t.Errorf("expected valid nested contentSchema payload to pass")
			}
			if !emptyIDOp.Evaluate(nil, `{"payload":"{}"}`) {
				t.Errorf("expected invalid nested contentSchema payload to trigger violation")
			}
		}

		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "huge-minlen.json",
			Root:      setupJSONSchema("huge-minlen.json", `{"type":"string","minLength":18446744073709551616}`),
		}); err == nil {
			t.Errorf("expected out-of-range minLength (2^64) to fail compilation instead of wrapping to 0")
		}

		// Without contains, v6.0.3 ignores minContains/maxContains, so out-of-range counts must not fail initialization.
		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "mincontains-no-contains.json",
			Root:      setupJSONSchema("mincontains-no-contains.json", `{"type":"array","minContains":18446744073709551616}`),
		}); err != nil {
			t.Errorf("expected minContains without contains to compile cleanly, got: %v", err)
		}
		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "mincontains-with-contains.json",
			Root:      setupJSONSchema("mincontains-with-contains.json", `{"type":"array","contains":{"type":"integer"},"minContains":18446744073709551616}`),
		}); err == nil {
			t.Errorf("expected out-of-range minContains alongside contains to fail compilation")
		}

		// Schema-like keys inside literal const/enum/default/examples must not trigger false compilation failures,
		// while actual schema locations (including properties named "const") remain guarded.
		if litOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "literal.json",
			Root: setupJSONSchema("literal.json", `{
				"type": "object",
				"const": {"minLength": -1, "contentMediaType": "application/yaml"},
				"default": {"minItems": 18446744073709551616},
				"examples": [{"maxLength": -5}]
			}`),
		}); err != nil {
			t.Fatalf("expected literal const/default/examples with schema-like keys to compile: %v", err)
		} else if litOp.Evaluate(nil, `{"minLength":-1,"contentMediaType":"application/yaml"}`) {
			t.Errorf("expected exact literal const match to pass")
		}
		if _, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "prop-const-huge.json",
			Root:      setupJSONSchema("prop-const-huge.json", `{"type":"object","properties":{"const":{"type":"string","minLength":18446744073709551616}}}`),
		}); err == nil {
			t.Errorf("expected out-of-range minLength under property named const to still fail compilation")
		}
	})

	t.Run("deep nesting and binary bytes do not panic", func(t *testing.T) {
		op, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "arr.json",
			Root:      setupJSONSchema("arr.json", `{"type":"array"}`),
		})
		if err != nil {
			t.Fatalf("compile array schema: %v", err)
		}
		deep := strings.Repeat("[", 1000) + "1" + strings.Repeat("]", 1000)
		if op.Evaluate(nil, deep) {
			t.Errorf("expected valid deep nested array to pass")
		}
		if op.Evaluate(nil, "[]") {
			t.Errorf("expected schema-valid empty array to pass")
		}
		if !op.Evaluate(nil, "\xef\xbb\xbf[]") {
			t.Errorf("expected BOM-prefixed schema-valid array to fail strict JSON parsing")
		}
		if !op.Evaluate(nil, "\xff\xfe\x00") {
			t.Errorf("expected raw binary bytes to trigger violation")
		}
	})

	t.Run("all drafts offline, custom dialect error, exact multipleOf, draft-07 formats, cyclic refs, and ReDoS", func(t *testing.T) {
		countingRT := &countingOfflineRoundTripper{}
		for _, metaschema := range []string{
			"http://json-schema.org/draft-04/schema#",
			"http://json-schema.org/draft-06/schema#",
			"http://json-schema.org/draft-07/schema#",
			"https://json-schema.org/draft/2019-09/schema",
			"https://json-schema.org/draft/2020-12/schema",
		} {
			op, err := newValidateSchema(plugintypes.OperatorOptions{
				Arguments: "draft.json",
				Root:      setupJSONSchema("draft.json", fmt.Sprintf(`{"$schema":%q,"type":"number","multipleOf":0.1}`, metaschema)),
			}, countingRT)
			if err != nil {
				t.Fatalf("compile draft %s offline: %v", metaschema, err)
			}
			if op.Evaluate(nil, `0.3`) {
				t.Errorf("draft %s: expected 0.3 to satisfy multipleOf 0.1", metaschema)
			}
			if !op.Evaluate(nil, `0.35`) {
				t.Errorf("draft %s: expected 0.35 to violate multipleOf 0.1", metaschema)
			}
		}
		if got := countingRT.calls.Load(); got != 0 {
			t.Errorf("expected built-in drafts to compile offline with 0 network requests, got %d", got)
		}

		if _, err := newValidateSchema(plugintypes.OperatorOptions{
			Arguments: "custom-dialect.json",
			Root:      setupJSONSchema("custom-dialect.json", `{"$schema":"https://dialect.invalid/custom/schema","type":"string"}`),
		}, countingRT); err == nil {
			t.Errorf("expected unreachable custom $schema dialect to fail initialization")
		} else if !strings.Contains(err.Error(), "resolving custom $schema dialect") {
			t.Errorf("expected actionable custom $schema dialect error, got: %v", err)
		}

		fmtOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "fmt.json",
			Root: setupJSONSchema("fmt.json", `{
				"$schema":"http://json-schema.org/draft-07/schema#",
				"type":"object",
				"properties":{
					"email":{"type":"string","format":"email"},
					"ip":{"type":"string","format":"ipv4"},
					"ts":{"type":"string","format":"date-time"}
				}
			}`),
		})
		if err != nil {
			t.Fatalf("compile draft-07 formats: %v", err)
		}
		if fmtOp.Evaluate(nil, `{"email":"user@example.com","ip":"192.0.2.1","ts":"2026-11-26T12:00:00Z"}`) {
			t.Errorf("expected valid formatted payload to pass")
		}
		if !fmtOp.Evaluate(nil, `{"email":"not-an-email"}`) || !fmtOp.Evaluate(nil, `{"ip":"999.999.999.999"}`) || !fmtOp.Evaluate(nil, `{"ts":"not-a-date"}`) {
			t.Errorf("expected invalid draft-07 formats to trigger violation")
		}

		cycOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "cyc.json",
			Root:      setupJSONSchema("cyc.json", `{"$defs":{"a":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`),
		})
		if err != nil {
			t.Fatalf("compile cyclic schema: %v", err)
		}
		if !cycOp.Evaluate(nil, `{}`) {
			t.Errorf("expected cyclic schema evaluation to fail closed without stack overflow")
		}

		redosOp, err := NewValidateSchema(plugintypes.OperatorOptions{
			Arguments: "redos.json",
			Root:      setupJSONSchema("redos.json", `{"type":"string","pattern":"^(a+)+$"}`),
		})
		if err != nil {
			t.Fatalf("compile pattern schema: %v", err)
		}
		if !redosOp.Evaluate(nil, `"`+strings.Repeat("a", 20000)+`!"`) {
			t.Errorf("expected ReDoS probe string to fail pattern quickly")
		}
	})
}

func BenchmarkValidateSchema(b *testing.B) {
	op, err := NewValidateSchema(plugintypes.OperatorOptions{
		Arguments: "schema.json",
		Root: setupJSONSchema("schema.json", `{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "object",
			"properties": {
				"name": { "type": "string", "minLength": 1 },
				"age": { "type": "integer", "minimum": 0 }
			},
			"required": ["name", "age"],
			"additionalProperties": false
		}`),
	})
	if err != nil {
		b.Fatalf("compile bench schema: %v", err)
	}
	valid := `{"name":"John","age":30}`
	invalid := `{"name":"","age":-1,"extra":true}`
	b.Run("valid", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if op.Evaluate(nil, valid) {
				b.Fatal("unexpected violation")
			}
		}
	})
	b.Run("invalid", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !op.Evaluate(nil, invalid) {
				b.Fatal("expected violation")
			}
		}
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type countingOfflineRoundTripper struct {
	calls atomic.Int64
}

func (rt *countingOfflineRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	return nil, errors.New("outbound network disabled during offline test or fuzzing")
}

func FuzzValidateSchema(f *testing.F) {
	offlineRT := &countingOfflineRoundTripper{}
	seeds := []struct {
		schema string
		body   string
	}{
		{`{"type":"object","properties":{"name":{"type":"string"},"age":{"type":"number"}},"required":["name","age"]}`, `{"name":"John","age":30}`},
		{`{"type":"object","properties":{"id":{"type":"integer"}},"required":["id"]}`, `{"id":9007199254740993}`},
		{`{"$schema":"http://json-schema.org/draft-07/schema#","type":"array","items":{"type":"string"}}`, `["a","b"]`},
		{`{"type":"object"}`, `{"a":1} trailing`},
		{`{"type":"object"}`, ``},
		{`{invalid`, `{"a":1}`},
		{`{"type":"object"}`, `null`},
		{`{"type":"number","minimum":0,"multipleOf":0.1}`, `1e-9999999999`},
		{`{"type":"number","minimum":0}`, `1e9999999999`},
		{`{"type":"array","uniqueItems":true}`, `[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,1e-9999999999]`},
		{`{"type":"string","contentEncoding":"base64","contentMediaType":"application/json","contentSchema":{"type":"number","minimum":0}}`, `"MWU5OTk5OTk5OTk5"`},
		{`{"type":"string","contentMediaType":"application/json","contentSchema":{"type":"number","minimum":0}}`, `"1e-9999999999"`},
	}
	for _, s := range seeds {
		f.Add(s.schema, s.body)
	}

	f.Fuzz(func(t *testing.T, rawSchema, body string) {
		rootFS := setupJSONSchema("schema.json", rawSchema)
		op, err := newValidateSchema(plugintypes.OperatorOptions{
			Arguments: "schema.json",
			Root:      rootFS,
		}, offlineRT)
		if err != nil {
			return
		}
		if op.Evaluate(nil, "") {
			t.Fatalf("empty input must not report violation")
		}
		_ = op.Evaluate(nil, body)
	})
}

func FuzzValidateSchemaBody(f *testing.F) {
	rootFS := setupJSONSchema("schema.json", `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$defs": {
			"item": {
				"type": "object",
				"properties": {
					"id": { "type": "integer", "minimum": 1, "maximum": 1000000 },
					"name": { "type": "string", "minLength": 1, "maxLength": 64, "pattern": "^[a-zA-Z0-9_-]+$" },
					"meta": {
						"oneOf": [
							{ "type": "null" },
							{ "type": "array", "items": { "type": "string" }, "maxItems": 8 }
						]
					}
				},
				"required": ["id", "name"],
				"additionalProperties": false
			}
		},
		"type": "object",
		"properties": {
			"action": { "enum": ["create", "update", "delete"] },
			"items": { "type": "array", "items": { "$ref": "#/$defs/item" }, "minItems": 1, "maxItems": 16 }
		},
		"required": ["action", "items"],
		"additionalProperties": false
	}`)

	op, err := NewValidateSchema(plugintypes.OperatorOptions{
		Arguments: "schema.json",
		Root:      rootFS,
	})
	if err != nil {
		f.Fatalf("Failed to compile fuzz schema: %v", err)
	}

	seeds := []string{
		``,
		`{}`,
		`null`,
		`[]`,
		`{"action":"create","items":[{"id":1,"name":"ok"}]}`,
		`{"action":"create","items":[{"id":1,"name":"ok","meta":["x","y"]}]}`,
		`{"action":"create","items":[{"id":1,"name":"ok","meta":null}]}`,
		`{"action":"create","items":[{"id":0,"name":"ok"}]}`,
		`{"action":"invalid","items":[]}`,
		`{"action":"create","items":[{"id":1,"name":"ok"}]} trailing`,
		`{"action":"create","items":` + strings.Repeat("[", 256) + `}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, body string) {
		if body == "" && op.Evaluate(nil, body) {
			t.Fatalf("empty input must not trigger violation")
		}
		direct := op.Evaluate(nil, body)
		if body != "" {
			txMap := collections.NewMap(variables.TX)
			txMap.Set("json_request_body", []string{body})
			tx := &mockTransaction{
				txVar:     txMap,
				lastPhase: types.PhaseRequestBody,
			}
			if txResult := op.Evaluate(tx, ""); txResult != direct {
				t.Fatalf("PhaseRequestBody mismatch for body %q: tx=%v direct=%v", body, txResult, direct)
			}
		}
	})
}
