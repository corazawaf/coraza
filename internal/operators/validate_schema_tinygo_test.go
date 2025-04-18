//go:build tinygo && !coraza.disabled_operators.validateSchema
// +build tinygo,!coraza.disabled_operators.validateSchema

package operators

import (
   "errors"
   "os"
   "path/filepath"
   "strings"
   "testing"
   "testing/fstest"

   "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestNewValidateSchema_MissingArg(t *testing.T) {
   _, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: ""})
   if err == nil || err.Error() != "schema file path is required" {
       t.Errorf("expected error 'schema file path is required', got %v", err)
   }
}

func TestNewValidateSchema_OSFileNotExist(t *testing.T) {
   // without Root, should use os.ReadFile
   _, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: "nonexistent.json"})
   if err == nil || !strings.HasPrefix(err.Error(), "failed to read schema file:") {
       t.Errorf("expected os read file error, got %v", err)
   }
}

func TestNewValidateSchema_OSFileSuccess(t *testing.T) {
   dir := t.TempDir()
   path := filepath.Join(dir, "schema.json")
   content := []byte(`{"foo":"bar"}`)
   if err := os.WriteFile(path, content, 0666); err != nil {
       t.Fatalf("failed to write temp file: %v", err)
   }
   op, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: path})
   if err != nil {
       t.Fatalf("expected no error, got %v", err)
   }
   vs, ok := op.(*validateSchema)
   if !ok {
       t.Fatalf("expected *validateSchema, got %T", op)
   }
   if vs.schemaType != "json" {
       t.Errorf("expected schemaType 'json', got '%s'", vs.schemaType)
   }
   if vs.schemaPath != path {
       t.Errorf("expected schemaPath '%s', got '%s'", path, vs.schemaPath)
   }
   if string(vs.schemaData) != string(content) {
       t.Errorf("expected schemaData '%s', got '%s'", string(content), string(vs.schemaData))
   }
}

func TestNewValidateSchema_FSFileNotExist(t *testing.T) {
   fsys := fstest.MapFS{}
   _, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: "schema.json", Root: fsys})
   if err == nil || !strings.HasPrefix(err.Error(), "failed to read schema file from root FS:") {
       t.Errorf("expected fs read file error, got %v", err)
   }
}

func TestNewValidateSchema_FSInvalidExt(t *testing.T) {
   fsys := fstest.MapFS{
       "schema.yaml": &fstest.MapFile{Data: []byte("{}")},
   }
   _, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: "schema.yaml", Root: fsys})
   if err == nil || !strings.Contains(err.Error(), "unsupported schema type: .yaml, must be .json") {
       t.Errorf("expected unsupported ext error, got %v", err)
   }
}

func TestNewValidateSchema_FSInvalidJSON(t *testing.T) {
   fsys := fstest.MapFS{
       "schema.json": &fstest.MapFile{Data: []byte("{invalid}")},
   }
   _, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: "schema.json", Root: fsys})
   if err == nil || !strings.HasPrefix(err.Error(), "invalid JSON schema:") {
       t.Errorf("expected invalid JSON schema error, got %v", err)
   }
}

func TestNewValidateSchema_FSSuccess(t *testing.T) {
   content := []byte(`{"hello":"world"}`)
   fsys := fstest.MapFS{
       "schema.json": &fstest.MapFile{Data: content},
   }
   op, err := NewValidateSchema(plugintypes.OperatorOptions{Arguments: "schema.json", Root: fsys})
   if err != nil {
       t.Fatalf("expected no error, got %v", err)
   }
   vs := op.(*validateSchema)
   if vs.schemaType != "json" {
       t.Errorf("expected schemaType 'json', got '%s'", vs.schemaType)
   }
   if vs.schemaPath != "schema.json" {
       t.Errorf("expected schemaPath 'schema.json', got '%s'", vs.schemaPath)
   }
   if string(vs.schemaData) != string(content) {
       t.Errorf("expected schemaData '%s', got '%s'", string(content), string(vs.schemaData))
   }
}

func TestEvaluate_NoTx(t *testing.T) {
   fsys := fstest.MapFS{"schema.json": &fstest.MapFile{Data: []byte("{}")}}
   op, _ := NewValidateSchema(plugintypes.OperatorOptions{Arguments: "schema.json", Root: fsys})
   // valid JSON should return false (no violation)
   if res := op.Evaluate(nil, `{"a":1}`); res {
       t.Errorf("expected false for valid JSON, got true")
   }
   // invalid JSON should return true (violation)
   if res := op.Evaluate(nil, `{`); !res {
       t.Errorf("expected true for invalid JSON, got false")
   }
   // empty data should return false
   if res := op.Evaluate(nil, ""); res {
       t.Errorf("expected false for empty data, got true")
   }
}

func TestIsValidJSON(t *testing.T) {
   vs := &validateSchema{}
   if !vs.isValidJSON(`{"x":2}`) {
       t.Errorf("expected true for valid JSON")
   }
   if vs.isValidJSON("notjson") {
       t.Errorf("expected false for invalid JSON")
   }
}
// TestEvaluate_InitError ensures Evaluate returns false when initialization fails
func TestEvaluate_InitError(t *testing.T) {
   // create operator with initError
   vs := &validateSchema{initError: errors.New("init failure")}
   // non-empty valid JSON should return false due to init error
   if res := vs.Evaluate(nil, `{"a":1}`); res {
       t.Errorf("expected false when initValidators error, got true")
   }
}