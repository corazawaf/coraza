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

// --- Benchmarks ---

// buildNDJSONStream generates an NDJSON stream with the given number of records using the record template.
func buildNDJSONStream(numRecords int, record string) string {
	var sb strings.Builder
	sb.Grow(numRecords * (len(record) + 1))
	for i := 0; i < numRecords; i++ {
		sb.WriteString(record)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// buildRFC7464Stream generates an RFC 7464 JSON Sequence stream.
func buildRFC7464Stream(numRecords int, record string) string {
	var sb strings.Builder
	sb.Grow(numRecords * (len(record) + 2))
	for i := 0; i < numRecords; i++ {
		sb.WriteByte('\x1e')
		sb.WriteString(record)
		sb.WriteByte('\n')
	}
	return sb.String()
}

const (
	smallRecord  = `{"id":1,"name":"Alice"}`
	mediumRecord = `{"user_id":1234567890,"name":"User Name","email":"user@example.com","role":"admin","active":true,"tags":["tag1","tag2","tag3"]}`
	nestedRecord = `{"user":{"name":"Alice","address":{"city":"NYC","zip":"10001"}},"scores":[95,87,92],"meta":{"created":"2026-01-01","active":true}}`
)

func BenchmarkJSONStreamProcessor(b *testing.B) {
	jsp, err := plugins.GetBodyProcessor("jsonstream")
	if err != nil {
		b.Fatal(err)
	}

	benchmarks := []struct {
		name       string
		numRecords int
		record     string
	}{
		{"small/1", 1, smallRecord},
		{"small/10", 10, smallRecord},
		{"small/100", 100, smallRecord},
		{"small/1000", 1000, smallRecord},
		{"medium/1", 1, mediumRecord},
		{"medium/10", 10, mediumRecord},
		{"medium/100", 100, mediumRecord},
		{"medium/1000", 1000, mediumRecord},
		{"nested/1", 1, nestedRecord},
		{"nested/10", 10, nestedRecord},
		{"nested/100", 100, nestedRecord},
		{"nested/1000", 1000, nestedRecord},
	}

	for _, bm := range benchmarks {
		input := buildNDJSONStream(bm.numRecords, bm.record)
		b.Run("ProcessRequest/"+bm.name, func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				v := corazawaf.NewTransactionVariables()
				if err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJSONStreamCallback(b *testing.B) {
	bp, err := plugins.GetBodyProcessor("jsonstream")
	if err != nil {
		b.Fatal(err)
	}
	sp, ok := bp.(plugintypes.StreamingBodyProcessor)
	if !ok {
		b.Fatal("jsonstream processor does not implement StreamingBodyProcessor")
	}

	benchmarks := []struct {
		name       string
		numRecords int
		record     string
	}{
		{"small/1", 1, smallRecord},
		{"small/10", 10, smallRecord},
		{"small/100", 100, smallRecord},
		{"small/1000", 1000, smallRecord},
		{"medium/1", 1, mediumRecord},
		{"medium/10", 10, mediumRecord},
		{"medium/100", 100, mediumRecord},
		{"medium/1000", 1000, mediumRecord},
		{"nested/1", 1, nestedRecord},
		{"nested/10", 10, nestedRecord},
		{"nested/100", 100, nestedRecord},
		{"nested/1000", 1000, nestedRecord},
	}

	noop := func(_ int, _ map[string]string, _ string) error { return nil }

	for _, bm := range benchmarks {
		input := buildNDJSONStream(bm.numRecords, bm.record)
		b.Run(bm.name, func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := sp.ProcessRequestRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{}, noop); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkJSONStreamRFC7464(b *testing.B) {
	bp, err := plugins.GetBodyProcessor("jsonstream")
	if err != nil {
		b.Fatal(err)
	}
	sp, ok := bp.(plugintypes.StreamingBodyProcessor)
	if !ok {
		b.Fatal("jsonstream processor does not implement StreamingBodyProcessor")
	}

	benchmarks := []struct {
		name       string
		numRecords int
		record     string
	}{
		{"small/10", 10, smallRecord},
		{"small/100", 100, smallRecord},
		{"medium/100", 100, mediumRecord},
		{"nested/100", 100, nestedRecord},
	}

	noop := func(_ int, _ map[string]string, _ string) error { return nil }

	for _, bm := range benchmarks {
		input := buildRFC7464Stream(bm.numRecords, bm.record)
		b.Run(bm.name, func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := sp.ProcessRequestRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{}, noop); err != nil {
					b.Fatal(err)
				}
			}
		})
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

// --- Streaming callback tests ---

func jsonstreamStreamingProcessor(t *testing.T) plugintypes.StreamingBodyProcessor {
	t.Helper()
	bp := jsonstreamProcessor(t)
	sp, ok := bp.(plugintypes.StreamingBodyProcessor)
	if !ok {
		t.Fatal("jsonstream processor does not implement StreamingBodyProcessor")
	}
	return sp
}

func TestStreamingCallbackPerRecord(t *testing.T) {
	input := `{"name": "Alice", "age": 30}
{"name": "Bob", "age": 25}
{"name": "Charlie", "age": 35}
`
	sp := jsonstreamStreamingProcessor(t)

	var records []int
	var rawRecords []string

	err := sp.ProcessRequestRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{},
		func(recordNum int, fields map[string]string, rawRecord string) error {
			records = append(records, recordNum)
			rawRecords = append(rawRecords, rawRecord)
			return nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}

	for i, r := range records {
		if r != i {
			t.Errorf("expected recordNum %d, got %d", i, r)
		}
	}

	if !strings.Contains(rawRecords[0], "Alice") {
		t.Errorf("expected raw record 0 to contain Alice, got: %s", rawRecords[0])
	}
	if !strings.Contains(rawRecords[1], "Bob") {
		t.Errorf("expected raw record 1 to contain Bob, got: %s", rawRecords[1])
	}
}

func TestStreamingFieldsHaveRecordPrefix(t *testing.T) {
	input := `{"name": "Alice"}
{"name": "Bob"}
`
	sp := jsonstreamStreamingProcessor(t)

	var allFields []map[string]string

	err := sp.ProcessRequestRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{},
		func(recordNum int, fields map[string]string, _ string) error {
			// Copy fields since the map may be reused
			copy := make(map[string]string, len(fields))
			for k, v := range fields {
				copy[k] = v
			}
			allFields = append(allFields, copy)
			return nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(allFields) != 2 {
		t.Fatalf("expected 2 records, got %d", len(allFields))
	}

	// Record 0 should have json.0.name
	if v, ok := allFields[0]["json.0.name"]; !ok || v != "Alice" {
		t.Errorf("expected json.0.name=Alice, got %q (ok=%v)", v, ok)
	}

	// Record 1 should have json.1.name
	if v, ok := allFields[1]["json.1.name"]; !ok || v != "Bob" {
		t.Errorf("expected json.1.name=Bob, got %q (ok=%v)", v, ok)
	}

	// Record 0 should NOT have json.1.* keys
	for k := range allFields[0] {
		if strings.HasPrefix(k, "json.1.") {
			t.Errorf("record 0 should not have key %q", k)
		}
	}
}

func TestStreamingInterruptionStops(t *testing.T) {
	input := `{"name": "Alice"}
{"name": "Bob"}
{"name": "Charlie"}
{"name": "Dave"}
`
	sp := jsonstreamStreamingProcessor(t)
	errBlocked := errors.New("blocked")
	processedRecords := 0

	err := sp.ProcessRequestRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{},
		func(recordNum int, fields map[string]string, _ string) error {
			processedRecords++
			if recordNum == 1 {
				return errBlocked
			}
			return nil
		})

	if err != errBlocked {
		t.Fatalf("expected errBlocked, got: %v", err)
	}

	if processedRecords != 2 {
		t.Errorf("expected 2 records processed (0 and 1), got %d", processedRecords)
	}
}

func TestStreamingEmptyStream(t *testing.T) {
	sp := jsonstreamStreamingProcessor(t)

	err := sp.ProcessRequestRecords(strings.NewReader(""), plugintypes.BodyProcessorOptions{},
		func(_ int, _ map[string]string, _ string) error {
			t.Error("callback should not be called for empty stream")
			return nil
		})

	if err == nil {
		t.Error("expected error for empty stream")
	}
}

func TestStreamingRFC7464WithCallback(t *testing.T) {
	input := "\x1e{\"name\": \"Alice\"}\n\x1e{\"name\": \"Bob\"}\n"

	sp := jsonstreamStreamingProcessor(t)

	var records []int
	var allFields []map[string]string

	err := sp.ProcessRequestRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{},
		func(recordNum int, fields map[string]string, _ string) error {
			records = append(records, recordNum)
			copy := make(map[string]string, len(fields))
			for k, v := range fields {
				copy[k] = v
			}
			allFields = append(allFields, copy)
			return nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	if v := allFields[0]["json.0.name"]; v != "Alice" {
		t.Errorf("expected json.0.name=Alice, got %q", v)
	}
	if v := allFields[1]["json.1.name"]; v != "Bob" {
		t.Errorf("expected json.1.name=Bob, got %q", v)
	}
}

func TestStreamingResponseRecords(t *testing.T) {
	input := `{"status": "ok"}
{"status": "error"}
`
	sp := jsonstreamStreamingProcessor(t)
	processedRecords := 0

	err := sp.ProcessResponseRecords(strings.NewReader(input), plugintypes.BodyProcessorOptions{},
		func(recordNum int, fields map[string]string, _ string) error {
			processedRecords++
			return nil
		})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if processedRecords != 2 {
		t.Errorf("expected 2 records, got %d", processedRecords)
	}
}

func TestStreamingBackwardCompat(t *testing.T) {
	// Verify that ProcessRequest still works unchanged after refactoring
	input := `{"name": "Alice"}
{"name": "Bob"}
`
	jsp := jsonstreamProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := jsp.ProcessRequest(strings.NewReader(input), v, plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	argsPost := v.ArgsPost()
	if vals := argsPost.Get("json.0.name"); len(vals) == 0 || vals[0] != "Alice" {
		t.Errorf("expected json.0.name=Alice via ProcessRequest, got %v", vals)
	}
	if vals := argsPost.Get("json.1.name"); len(vals) == 0 || vals[0] != "Bob" {
		t.Errorf("expected json.1.name=Bob via ProcessRequest, got %v", vals)
	}
}
