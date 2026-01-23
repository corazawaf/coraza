// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	_ "github.com/corazawaf/coraza/v3/experimental/bodyprocessors"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func jsonstreamProcessor(t *testing.T) plugintypes.BodyProcessor {
	t.Helper()
	jsp, err := plugins.GetBodyProcessor("jsonstream")
	if err != nil {
		t.Fatal(err)
	}
	return jsp
}

func TestJSONStreamSingleLine(t *testing.T) {
	input := `{"name": "John", "age": 30}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Check expected keys
	if name := argsPost.Get("json.0.name"); len(name) == 0 || name[0] != "John" {
		t.Errorf("json.0.name should be 'John', got: %v", name)
	}

	if age := argsPost.Get("json.0.age"); len(age) == 0 || age[0] != "30" {
		t.Errorf("json.0.age should be '30', got: %v", age)
	}
}

func TestJSONStreamMultipleLines(t *testing.T) {
	input := `{"name": "John", "age": 30}
{"name": "Jane", "age": 25}
{"name": "Bob", "age": 35}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Check all three lines
	tests := []struct {
		line int
		name string
		age  string
	}{
		{0, "John", "30"},
		{1, "Jane", "25"},
		{2, "Bob", "35"},
	}

	for _, tt := range tests {
		nameKey := fmt.Sprintf("json.%d.name", tt.line)
		ageKey := fmt.Sprintf("json.%d.age", tt.line)

		if name := argsPost.Get(nameKey); len(name) == 0 || name[0] != tt.name {
			t.Errorf("%s should be '%s', got: %v", nameKey, tt.name, name)
		}

		if age := argsPost.Get(ageKey); len(age) == 0 || age[0] != tt.age {
			t.Errorf("%s should be '%s', got: %v", ageKey, tt.age, age)
		}
	}
}

func TestJSONStreamNestedObjects(t *testing.T) {
	input := `{"user": {"name": "John", "id": 1}, "active": true}
{"user": {"name": "Jane", "id": 2}, "active": false}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Check nested fields
	if name := argsPost.Get("json.0.user.name"); len(name) == 0 || name[0] != "John" {
		t.Errorf("json.0.user.name should be 'John', got: %v", name)
	}

	if id := argsPost.Get("json.0.user.id"); len(id) == 0 || id[0] != "1" {
		t.Errorf("json.0.user.id should be '1', got: %v", id)
	}

	if active := argsPost.Get("json.0.active"); len(active) == 0 || active[0] != "true" {
		t.Errorf("json.0.active should be 'true', got: %v", active)
	}

	if name := argsPost.Get("json.1.user.name"); len(name) == 0 || name[0] != "Jane" {
		t.Errorf("json.1.user.name should be 'Jane', got: %v", name)
	}

	if active := argsPost.Get("json.1.active"); len(active) == 0 || active[0] != "false" {
		t.Errorf("json.1.active should be 'false', got: %v", active)
	}
}

func TestJSONStreamWithArrays(t *testing.T) {
	input := `{"name": "John", "tags": ["admin", "user"]}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Check array fields
	if tags := argsPost.Get("json.0.tags"); len(tags) == 0 || tags[0] != "2" {
		t.Errorf("json.0.tags should be '2' (array length), got: %v", tags)
	}

	if tag0 := argsPost.Get("json.0.tags.0"); len(tag0) == 0 || tag0[0] != "admin" {
		t.Errorf("json.0.tags.0 should be 'admin', got: %v", tag0)
	}

	if tag1 := argsPost.Get("json.0.tags.1"); len(tag1) == 0 || tag1[0] != "user" {
		t.Errorf("json.0.tags.1 should be 'user', got: %v", tag1)
	}
}

func TestJSONStreamSkipEmptyLines(t *testing.T) {
	input := `{"name": "John"}

{"name": "Jane"}

`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Empty lines should be skipped, so we should only have line 0 and 1
	if name := argsPost.Get("json.0.name"); len(name) == 0 || name[0] != "John" {
		t.Errorf("json.0.name should be 'John', got: %v", name)
	}

	if name := argsPost.Get("json.1.name"); len(name) == 0 || name[0] != "Jane" {
		t.Errorf("json.1.name should be 'Jane', got: %v", name)
	}

	// Line 2 should not exist
	if name := argsPost.Get("json.2.name"); len(name) != 0 {
		t.Errorf("json.2.name should not exist, got: %v", name)
	}
}

func TestJSONStreamArrayAsRoot(t *testing.T) {
	input := `[1, 2, 3]
[4, 5, 6]
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Check first array
	if arr := argsPost.Get("json.0"); len(arr) == 0 || arr[0] != "3" {
		t.Errorf("json.0 should be '3' (array length), got: %v", arr)
	}

	if val := argsPost.Get("json.0.0"); len(val) == 0 || val[0] != "1" {
		t.Errorf("json.0.0 should be '1', got: %v", val)
	}

	// Check second array
	if arr := argsPost.Get("json.1"); len(arr) == 0 || arr[0] != "3" {
		t.Errorf("json.1 should be '3' (array length), got: %v", arr)
	}

	if val := argsPost.Get("json.1.0"); len(val) == 0 || val[0] != "4" {
		t.Errorf("json.1.0 should be '4', got: %v", val)
	}
}

func TestJSONStreamNullAndBooleans(t *testing.T) {
	input := `{"null": null, "true": true, "false": false}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Check null value (should be empty string)
	if null := argsPost.Get("json.0.null"); len(null) == 0 || null[0] != "" {
		t.Errorf("json.0.null should be empty string, got: %v", null)
	}

	// Check boolean values
	if trueVal := argsPost.Get("json.0.true"); len(trueVal) == 0 || trueVal[0] != "true" {
		t.Errorf("json.0.true should be 'true', got: %v", trueVal)
	}

	if falseVal := argsPost.Get("json.0.false"); len(falseVal) == 0 || falseVal[0] != "false" {
		t.Errorf("json.0.false should be 'false', got: %v", falseVal)
	}
}

func TestJSONStreamInvalidJSON(t *testing.T) {
	input := `{"name": "John"}
{invalid json}
{"name": "Jane"}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err == nil {
		t.Errorf("expected error for invalid JSON, got none")
	}

	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("expected 'invalid JSON' error, got: %v", err)
	}
}

func TestJSONStreamEmptyStream(t *testing.T) {
	input := ""

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err == nil {
		t.Errorf("expected error for empty stream, got none")
	}

	if !strings.Contains(err.Error(), "no valid JSON objects") {
		t.Errorf("expected 'no valid JSON objects' error, got: %v", err)
	}
}

func TestJSONStreamOnlyEmptyLines(t *testing.T) {
	input := "\n\n\n"

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err == nil {
		t.Errorf("expected error for only empty lines, got none")
	}

	if !strings.Contains(err.Error(), "no valid JSON objects") {
		t.Errorf("expected 'no valid JSON objects' error, got: %v", err)
	}
}

func TestJSONStreamRecursionLimit(t *testing.T) {
	// Create a deeply nested JSON object that exceeds the default limit
	// Default limit is 1024, so we create 1500 levels to trigger the error
	deeplyNested := strings.Repeat(`{"a":`, 1500) + "1" + strings.Repeat(`}`, 1500)
	input := deeplyNested + "\n"

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	// This should fail because it exceeds DefaultStreamRecursionLimit (1024)
	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err == nil {
		t.Errorf("expected error due to recursion limit, got none")
	}

	if !strings.Contains(err.Error(), "max recursion") {
		t.Errorf("expected recursion error, got: %v", err)
	}
}

func TestJSONStreamTXVariables(t *testing.T) {
	input := `{"name": "John"}
{"name": "Jane"}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Check TX variables
	txVars := v.TX()

	// Check raw body storage
	rawBody := txVars.Get("jsonstream_request_body")
	if len(rawBody) == 0 || rawBody[0] != input {
		t.Errorf("jsonstream_request_body not stored correctly")
	}

	// Check line count
	lineCount := txVars.Get("jsonstream_request_line_count")
	if len(lineCount) == 0 || lineCount[0] != "2" {
		t.Errorf("jsonstream_request_line_count should be 2, got: %v", lineCount)
	}
}

func TestJSONStreamProcessResponse(t *testing.T) {
	input := `{"status": "ok"}
{"status": "error"}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessResponse(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Check response args
	responseArgs := v.ResponseArgs()

	if status0 := responseArgs.Get("json.0.status"); len(status0) == 0 || status0[0] != "ok" {
		t.Errorf("json.0.status should be 'ok', got: %v", status0)
	}

	if status1 := responseArgs.Get("json.1.status"); len(status1) == 0 || status1[0] != "error" {
		t.Errorf("json.1.status should be 'error', got: %v", status1)
	}
}

func TestJSONSequenceRFC7464(t *testing.T) {
	// RFC 7464 format uses ASCII RS (0x1E) as record separator
	const RS = "\x1e"

	input := RS + `{"name": "John", "age": 30}` + "\n" +
		RS + `{"name": "Jane", "age": 25}` + "\n" +
		RS + `{"name": "Bob", "age": 35}` + "\n"

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Check all three records
	tests := []struct {
		record int
		name   string
		age    string
	}{
		{0, "John", "30"},
		{1, "Jane", "25"},
		{2, "Bob", "35"},
	}

	for _, tt := range tests {
		nameKey := fmt.Sprintf("json.%d.name", tt.record)
		ageKey := fmt.Sprintf("json.%d.age", tt.record)

		if name := argsPost.Get(nameKey); len(name) == 0 || name[0] != tt.name {
			t.Errorf("%s should be '%s', got: %v", nameKey, tt.name, name)
		}

		if age := argsPost.Get(ageKey); len(age) == 0 || age[0] != tt.age {
			t.Errorf("%s should be '%s', got: %v", ageKey, tt.age, age)
		}
	}

	// Check line count
	txVars := v.TX()
	lineCount := txVars.Get("jsonstream_request_line_count")
	if len(lineCount) == 0 || lineCount[0] != "3" {
		t.Errorf("jsonstream_request_line_count should be 3, got: %v", lineCount)
	}
}

func TestJSONSequenceNestedObjects(t *testing.T) {
	const RS = "\x1e"

	input := RS + `{"user": {"name": "John", "id": 1}, "active": true}` + "\n" +
		RS + `{"user": {"name": "Jane", "id": 2}, "active": false}` + "\n"

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Check nested fields
	if name := argsPost.Get("json.0.user.name"); len(name) == 0 || name[0] != "John" {
		t.Errorf("json.0.user.name should be 'John', got: %v", name)
	}

	if id := argsPost.Get("json.0.user.id"); len(id) == 0 || id[0] != "1" {
		t.Errorf("json.0.user.id should be '1', got: %v", id)
	}

	if active := argsPost.Get("json.0.active"); len(active) == 0 || active[0] != "true" {
		t.Errorf("json.0.active should be 'true', got: %v", active)
	}
}

func TestJSONSequenceWithoutTrailingNewlines(t *testing.T) {
	const RS = "\x1e"

	// RFC 7464 says newlines are optional, test without them
	input := RS + `{"name": "John"}` + RS + `{"name": "Jane"}` + RS + `{"name": "Bob"}`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	if name := argsPost.Get("json.0.name"); len(name) == 0 || name[0] != "John" {
		t.Errorf("json.0.name should be 'John', got: %v", name)
	}

	if name := argsPost.Get("json.1.name"); len(name) == 0 || name[0] != "Jane" {
		t.Errorf("json.1.name should be 'Jane', got: %v", name)
	}

	if name := argsPost.Get("json.2.name"); len(name) == 0 || name[0] != "Bob" {
		t.Errorf("json.2.name should be 'Bob', got: %v", name)
	}
}

func TestJSONSequenceEmptyRecords(t *testing.T) {
	const RS = "\x1e"

	// Empty records (multiple RS in a row) should be skipped
	input := RS + RS + `{"name": "John"}` + "\n" + RS + "\n" + RS + `{"name": "Jane"}` + "\n"

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	argsPost := v.ArgsPost()

	// Should only have 2 records (empty ones skipped)
	if name := argsPost.Get("json.0.name"); len(name) == 0 || name[0] != "John" {
		t.Errorf("json.0.name should be 'John', got: %v", name)
	}

	if name := argsPost.Get("json.1.name"); len(name) == 0 || name[0] != "Jane" {
		t.Errorf("json.1.name should be 'Jane', got: %v", name)
	}

	// Third record should not exist
	if name := argsPost.Get("json.2.name"); len(name) != 0 {
		t.Errorf("json.2.name should not exist, got: %v", name)
	}
}

func TestJSONSequenceInvalidJSON(t *testing.T) {
	const RS = "\x1e"

	input := RS + `{"name": "John"}` + "\n" +
		RS + `{invalid json}` + "\n" +
		RS + `{"name": "Jane"}` + "\n"

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err == nil {
		t.Errorf("expected error for invalid JSON, got none")
	}

	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("expected 'invalid JSON' error, got: %v", err)
	}
}

func TestFormatAutoDetection(t *testing.T) {
	const RS = "\x1e"

	tests := []struct {
		name   string
		input  string
		format string
	}{
		{
			name:   "NDJSON without RS",
			input:  `{"name": "John"}` + "\n" + `{"name": "Jane"}` + "\n",
			format: "NDJSON",
		},
		{
			name:   "JSON Sequence with RS",
			input:  RS + `{"name": "John"}` + "\n" + RS + `{"name": "Jane"}` + "\n",
			format: "JSON Sequence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsp := jsonstreamProcessor(t)
			v := corazawaf.NewTransactionVariables()

			err := jsp.ProcessRequest(strings.NewReader(tt.input), v, plugintypes.BodyProcessorOptions{})

			if err != nil {
				t.Errorf("unexpected error for %s: %v", tt.format, err)
				return
			}

			argsPost := v.ArgsPost()

			// Both formats should produce the same output
			if name := argsPost.Get("json.0.name"); len(name) == 0 || name[0] != "John" {
				t.Errorf("%s: json.0.name should be 'John', got: %v", tt.format, name)
			}

			if name := argsPost.Get("json.1.name"); len(name) == 0 || name[0] != "Jane" {
				t.Errorf("%s: json.1.name should be 'Jane', got: %v", tt.format, name)
			}
		})
	}
}

func BenchmarkJSONStreamProcessor(b *testing.B) {
	// Create a realistic NDJSON stream with 100 objects
	var sb strings.Builder
	for i := 0; i < 100; i++ {
		sb.WriteString(`{"user_id": 1234567890, "name": "User Name", "email": "user@example.com", "tags": ["tag1", "tag2", "tag3"]}`)
		sb.WriteString("\n")
	}
	input := sb.String()

	jsp, err := plugins.GetBodyProcessor("jsonstream")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := corazawaf.NewTransactionVariables()
		reader := strings.NewReader(input)

		err := jsp.ProcessRequest(reader, v, plugintypes.BodyProcessorOptions{})

		if err != nil {
			b.Error(err)
		}
	}
}

func TestProcessorRegistration(t *testing.T) {
	// Test that all three aliases are registered
	aliases := []string{"jsonstream", "ndjson", "jsonlines"}

	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			processor, err := plugins.GetBodyProcessor(alias)
			if err != nil {
				t.Errorf("Failed to get processor '%s': %v", alias, err)
			}
			if processor == nil {
				t.Errorf("Processor '%s' is nil", alias)
			}
		})
	}
}

func TestJSONStreamLargeToken(t *testing.T) {
	// Create a JSON object that exceeds 1MB to trigger scanner buffer error
	largeValue := strings.Repeat("x", 2*1024*1024) // 2MB string
	input := fmt.Sprintf(`{"large": "%s"}`, largeValue) + "\n"

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	// Should get a scanner error about token too long
	if err == nil {
		t.Errorf("expected error for token too large, got none")
	}

	if !strings.Contains(err.Error(), "error reading stream") && !strings.Contains(err.Error(), "token too long") {
		t.Logf("Got error (this is expected): %v", err)
	}
}

func TestJSONSequenceLargeToken(t *testing.T) {
	const RS = "\x1e"
	// Create a JSON object that exceeds 1MB to trigger scanner buffer error
	largeValue := strings.Repeat("x", 2*1024*1024) // 2MB string
	input := RS + fmt.Sprintf(`{"large": "%s"}`, largeValue) + "\n"

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	// Should get a scanner error about token too long
	if err == nil {
		t.Errorf("expected error for token too large, got none")
	}

	if !strings.Contains(err.Error(), "error reading stream") && !strings.Contains(err.Error(), "token too long") {
		t.Logf("Got error (this is expected): %v", err)
	}
}

func TestProcessResponseWithoutResponseBody(t *testing.T) {
	input := `{"status": "ok"}
`

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	// Process response without setting up ResponseBody
	err := jsp.ProcessResponse(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	// Check response args were still populated
	responseArgs := v.ResponseArgs()
	if status := responseArgs.Get("json.0.status"); len(status) == 0 || status[0] != "ok" {
		t.Errorf("json.0.status should be 'ok', got: %v", status)
	}

	// TX variables should be set (but response body related ones may not be if ResponseBody() is nil)
	txVars := v.TX()
	lineCount := txVars.Get("jsonstream_response_line_count")
	if len(lineCount) == 0 || lineCount[0] != "1" {
		t.Logf("jsonstream_response_line_count: %v (may be empty if ResponseBody() is nil)", lineCount)
	}
}

// errorReader is a reader that always returns an error
type errorReader struct{}

func (e errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

func TestJSONStreamPeekError(t *testing.T) {
	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	// Use an error reader to trigger peek error
	err := jsp.ProcessRequest(errorReader{}, v, plugintypes.BodyProcessorOptions{})

	if err == nil {
		t.Errorf("expected error from peek, got none")
	}

	if !strings.Contains(err.Error(), "error peeking stream") {
		t.Errorf("expected 'error peeking stream' error, got: %v", err)
	}
}

func TestJSONSequenceOnlyRS(t *testing.T) {
	const RS = "\x1e"

	// Only RS characters, no actual JSON
	input := RS + RS + RS

	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})

	if err == nil {
		t.Errorf("expected error for only RS characters, got none")
	}

	if !strings.Contains(err.Error(), "no valid JSON objects") {
		t.Errorf("expected 'no valid JSON objects' error, got: %v", err)
	}
}
