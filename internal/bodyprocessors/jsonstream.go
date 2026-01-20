// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

const (
	// DefaultStreamRecursionLimit is the default recursion limit for streaming JSON processing
	// This protects against deeply nested JSON objects in each line
	DefaultStreamRecursionLimit = 1024
)

// jsonStreamBodyProcessor handles streaming JSON formats like NDJSON (Newline Delimited JSON).
// Each line in the input is expected to be a complete, valid JSON object.
// Empty lines are ignored. Each JSON object is flattened and indexed by line number.
//
// Supported formats:
// - NDJSON (application/x-ndjson): Each line is a complete JSON object
// - JSON Lines (application/jsonlines): Alias for NDJSON
//
// Note: RFC 7464 JSON Sequence format (with ASCII RS 0x1E record separator) is not yet implemented.
type jsonStreamBodyProcessor struct{}

var _ plugintypes.BodyProcessor = &jsonStreamBodyProcessor{}

func (js *jsonStreamBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	col := v.ArgsPost()

	// Store the raw body for TX variables.
	// Note: This creates a memory copy of the entire body, similar to the regular JSON processor.
	// This is necessary for operators like @validateSchema that need access to the raw content.
	// Memory usage: 2x the body size (once in buffer, once in parsed variables)
	var rawBody strings.Builder

	// Create a TeeReader to read the body and store it simultaneously
	tee := io.TeeReader(reader, &rawBody)

	// Use default recursion limit for now
	// TODO: Use RequestBodyRecursionLimit from BodyProcessorOptions when available
	lineNum, err := processJSONStream(tee, col, DefaultStreamRecursionLimit)
	if err != nil {
		return err
	}

	// Store the raw JSON stream in the TX variable for potential validation
	if txVar := v.TX(); txVar != nil {
		txVar.Set("jsonstream_request_body", []string{rawBody.String()})
		txVar.Set("jsonstream_request_line_count", []string{strconv.Itoa(lineNum)})
	}

	return nil
}

func (js *jsonStreamBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	col := v.ResponseArgs()

	// Store the raw body for TX variables.
	// Note: This creates a memory copy of the entire body, similar to the regular JSON processor.
	// Memory usage: 2x the body size (once in buffer, once in parsed variables)
	var rawBody strings.Builder

	// Create a TeeReader to read the body and store it simultaneously
	tee := io.TeeReader(reader, &rawBody)

	// Use default recursion limit for response bodies too
	// TODO: Consider using a different limit for responses when configurable
	lineNum, err := processJSONStream(tee, col, DefaultStreamRecursionLimit)
	if err != nil {
		return err
	}

	// Store the raw JSON stream in the TX variable for potential validation
	if txVar := v.TX(); txVar != nil && v.ResponseBody() != nil {
		txVar.Set("jsonstream_response_body", []string{rawBody.String()})
		txVar.Set("jsonstream_response_line_count", []string{strconv.Itoa(lineNum)})
	}

	return nil
}

// processJSONStream processes a stream of JSON objects line by line.
// Each line is expected to be a complete JSON object (NDJSON format).
// Returns the number of lines processed and any error encountered.
func processJSONStream(reader io.Reader, col interface {
	SetIndex(string, int, string)
}, maxRecursion int) (int, error) {
	scanner := bufio.NewScanner(reader)

	// Increase scanner buffer to handle large JSON objects (default is 64KB)
	// Set max to 1MB to match typical JSON object sizes while preventing memory exhaustion
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxScanTokenSize)

	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Validate JSON before parsing
		if !gjson.Valid(line) {
			// Use 1-based line numbering for user-friendly error messages
			return lineNum, fmt.Errorf("invalid JSON at line %d", lineNum+1)
		}

		// Parse the JSON line using the existing readJSON function
		data, err := readJSONWithLimit(line, maxRecursion)
		if err != nil {
			// Use 1-based line numbering for user-friendly error messages
			return lineNum, fmt.Errorf("error parsing JSON at line %d: %w", lineNum+1, err)
		}

		// Add each key-value pair with a line number prefix
		// Example: json.0.field, json.1.field, etc.
		for key, value := range data {
			// Replace the "json" prefix with "json.{lineNum}"
			// Original key format: "json.field.subfield"
			// New key format: "json.0.field.subfield"
			if strings.HasPrefix(key, "json.") {
				key = fmt.Sprintf("json.%d.%s", lineNum, key[5:]) // Skip "json."
			} else if key == "json" {
				key = fmt.Sprintf("json.%d", lineNum)
			}
			col.SetIndex(key, 0, value)
		}

		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return lineNum, fmt.Errorf("error reading stream: %w", err)
	}

	// If we processed zero lines, that might indicate an issue
	if lineNum == 0 {
		return 0, errors.New("no valid JSON objects found in stream")
	}

	return lineNum, nil
}

// readJSONWithLimit is a helper that calls readJSON but with protection against deep nesting
// TODO: Remove this when readJSON supports maxRecursion parameter natively
func readJSONWithLimit(s string, maxRecursion int) (map[string]string, error) {
	json := gjson.Parse(s)
	res := make(map[string]string)
	key := []byte("json")
	err := readItemsWithLimit(json, key, maxRecursion, res)
	return res, err
}

// readItemsWithLimit is similar to readItems but with recursion limit
// TODO: Remove this when readItems supports maxRecursion parameter natively
func readItemsWithLimit(json gjson.Result, objKey []byte, maxRecursion int, res map[string]string) error {
	arrayLen := 0
	var iterationError error

	if maxRecursion == 0 {
		return errors.New("max recursion reached while reading json object")
	}

	json.ForEach(func(key, value gjson.Result) bool {
		prevParentLength := len(objKey)
		objKey = append(objKey, '.')
		if key.Type == gjson.String {
			objKey = append(objKey, key.Str...)
		} else {
			objKey = strconv.AppendInt(objKey, int64(key.Num), 10)
			arrayLen++
		}

		var val string
		switch value.Type {
		case gjson.JSON:
			iterationError = readItemsWithLimit(value, objKey, maxRecursion-1, res)
			if iterationError != nil {
				return false
			}
			objKey = objKey[:prevParentLength]
			return true
		case gjson.String:
			val = value.Str
		case gjson.Null:
			val = ""
		default:
			val = value.Raw
		}

		res[string(objKey)] = val
		objKey = objKey[:prevParentLength]

		return true
	})
	if arrayLen > 0 {
		res[string(objKey)] = strconv.Itoa(arrayLen)
	}
	return iterationError
}

func init() {
	// Register the processor with multiple names for different content-types
	RegisterBodyProcessor("jsonstream", func() plugintypes.BodyProcessor {
		return &jsonStreamBodyProcessor{}
	})
	RegisterBodyProcessor("ndjson", func() plugintypes.BodyProcessor {
		return &jsonStreamBodyProcessor{}
	})
	RegisterBodyProcessor("jsonlines", func() plugintypes.BodyProcessor {
		return &jsonStreamBodyProcessor{}
	})
}
