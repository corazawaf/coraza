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

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

const (
	// DefaultStreamRecursionLimit is the default recursion limit for streaming JSON processing
	// This protects against deeply nested JSON objects in each line
	DefaultStreamRecursionLimit = 1024

	// recordSeparator is the ASCII RS character (0x1E) used in RFC 7464 JSON Sequences
	recordSeparator = '\x1e'
)

// jsonStreamBodyProcessor handles streaming JSON formats.
// Each record/line in the input is expected to be a complete, valid JSON object.
// Empty lines are ignored. Each JSON object is flattened and indexed by record number.
//
// Supported formats:
// - NDJSON (application/x-ndjson): Each line is a complete JSON object
// - JSON Lines (application/jsonlines): Alias for NDJSON
// - JSON Sequence (application/json-seq): RFC 7464 format with RS (0x1E) record separator
//
// The processor auto-detects the format based on the presence of RS characters.
type jsonStreamBodyProcessor struct{}

var _ plugintypes.StreamingBodyProcessor = &jsonStreamBodyProcessor{}

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

// processJSONStream processes a stream of JSON objects incrementally.
// Supports both NDJSON (newline-delimited) and RFC 7464 JSON Sequence (RS-delimited) formats.
// The format is auto-detected by peeking at the first chunk of data.
// Returns the number of records processed and any error encountered.
func processJSONStream(reader io.Reader, col interface {
	SetIndex(string, int, string)
}, maxRecursion int) (int, error) {
	return processJSONStreamWithCallback(reader, maxRecursion, func(_ int, fields map[string]string, _ string) error {
		for key, value := range fields {
			col.SetIndex(key, 0, value)
		}
		return nil
	})
}

// processJSONStreamWithCallback processes a stream of JSON objects, calling fn for each record.
// The callback receives the record number, a map of pre-formatted fields (with record-prefixed keys
// like "json.0.name"), and the raw record text. If fn returns a non-nil error, processing stops.
// Returns the number of records processed and any error encountered.
func processJSONStreamWithCallback(reader io.Reader, maxRecursion int,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) (int, error) {
	bufReader := bufio.NewReader(reader)

	// Peek at the first chunk to detect format without consuming the entire stream
	// Use 4KB as a reasonable peek size - enough to detect RS in typical streams
	peekSize := 4096
	peekBytes, err := bufReader.Peek(peekSize)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return 0, fmt.Errorf("error peeking stream: %w", err)
	}

	// Check if we have any data at all
	if len(peekBytes) == 0 {
		return 0, errors.New("no valid JSON objects found in stream")
	}

	// Auto-detect format: if peek contains RS characters, use JSON Sequence parsing
	// Otherwise, use NDJSON (newline) parsing
	if containsRS(peekBytes) {
		return processJSONSequenceStreamWithCallback(bufReader, maxRecursion, fn)
	}
	return processNDJSONStreamWithCallback(bufReader, maxRecursion, fn)
}

// containsRS checks if a byte slice contains the RS character
func containsRS(data []byte) bool {
	for _, b := range data {
		if b == recordSeparator {
			return true
		}
	}
	return false
}

// newRecordScanner creates a bufio.Scanner with the standard buffer sizes used for JSON record scanning.
func newRecordScanner(reader io.Reader, split bufio.SplitFunc) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	if split != nil {
		scanner.Split(split)
	}

	// Increase scanner buffer to handle large JSON objects (default is 64KB)
	// Set max to 1MB to match typical JSON object sizes while preventing memory exhaustion
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxScanTokenSize)

	return scanner
}

// scanRecords iterates over scanner records, parsing each as JSON and calling fn.
// Shared logic for both NDJSON and RFC 7464 processing.
func scanRecords(scanner *bufio.Scanner, maxRecursion int,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) (int, error) {
	recordNum := 0

	for scanner.Scan() {
		record := strings.TrimSpace(scanner.Text())
		if record == "" {
			continue
		}

		fields, err := parseJSONRecord(record, recordNum, maxRecursion)
		if err != nil {
			return recordNum, err
		}

		if err := fn(recordNum, fields, record); err != nil {
			return recordNum + 1, err
		}

		recordNum++
	}

	if err := scanner.Err(); err != nil {
		return recordNum, fmt.Errorf("error reading stream: %w", err)
	}

	if recordNum == 0 {
		return 0, errors.New("no valid JSON objects found in stream")
	}

	return recordNum, nil
}

// processNDJSONStreamWithCallback processes NDJSON format (newline-delimited JSON objects) from a reader,
// calling fn for each record.
func processNDJSONStreamWithCallback(reader io.Reader, maxRecursion int,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) (int, error) {
	return scanRecords(newRecordScanner(reader, nil), maxRecursion, fn)
}

// processJSONSequenceStreamWithCallback processes RFC 7464 JSON Sequence format (RS-delimited JSON objects)
// from a reader, calling fn for each record.
func processJSONSequenceStreamWithCallback(reader io.Reader, maxRecursion int,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) (int, error) {
	return scanRecords(newRecordScanner(reader, splitOnRS), maxRecursion, fn)
}

// splitOnRS is a custom split function for bufio.Scanner that splits on RS (0x1E) characters.
// This enables streaming processing of RFC 7464 JSON Sequence format.
func splitOnRS(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading RS characters
	start := 0
	for start < len(data) && data[start] == recordSeparator {
		start++
	}

	// If we've consumed all data and we're at EOF, we're done
	if atEOF && start >= len(data) {
		return len(data), nil, nil
	}

	// Find the next RS character after start
	for i := start; i < len(data); i++ {
		if data[i] == recordSeparator {
			// Found RS, return the record between start and i
			return i + 1, data[start:i], nil
		}
	}

	// If we're at EOF, return remaining data as the last record
	if atEOF && start < len(data) {
		return len(data), data[start:], nil
	}

	// Request more data
	return 0, nil, nil
}

// parseJSONRecord parses a single JSON record and returns a map of fields with record-prefixed keys.
// Keys are formatted as "json.{recordNum}.field.subfield".
func parseJSONRecord(jsonText string, recordNum int, maxRecursion int) (map[string]string, error) {
	// Validate JSON before parsing
	if !gjson.Valid(jsonText) {
		// Use 1-based numbering for user-friendly error messages
		return nil, fmt.Errorf("invalid JSON at record %d", recordNum+1)
	}

	// Parse the JSON record
	data, err := readJSONWithLimit(jsonText, maxRecursion)
	if err != nil {
		// Use 1-based numbering for user-friendly error messages
		return nil, fmt.Errorf("error parsing JSON at record %d: %w", recordNum+1, err)
	}

	// Build result with record-prefixed keys
	// Example: json.0.field, json.1.field, etc.
	fields := make(map[string]string, len(data))
	for key, value := range data {
		// Replace the "json" prefix with "json.{recordNum}"
		// Original key format: "json.field.subfield"
		// New key format: "json.0.field.subfield"
		if strings.HasPrefix(key, "json.") {
			key = fmt.Sprintf("json.%d.%s", recordNum, key[5:]) // Skip "json."
		} else if key == "json" {
			key = fmt.Sprintf("json.%d", recordNum)
		}
		fields[key] = value
	}

	return fields, nil
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

func (js *jsonStreamBodyProcessor) ProcessRequestRecords(reader io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) error {
	recordCount, err := processJSONStreamWithCallback(reader, DefaultStreamRecursionLimit, fn)
	if err != nil {
		return err
	}
	if recordCount == 0 {
		return errors.New("no valid JSON objects found in stream")
	}
	return nil
}

func (js *jsonStreamBodyProcessor) ProcessResponseRecords(reader io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) error {
	recordCount, err := processJSONStreamWithCallback(reader, DefaultStreamRecursionLimit, fn)
	if err != nil {
		return err
	}
	if recordCount == 0 {
		return errors.New("no valid JSON objects found in stream")
	}
	return nil
}

func init() {
	// Register the processor with multiple names for different content-types
	plugins.RegisterBodyProcessor("jsonstream", func() plugintypes.BodyProcessor {
		return &jsonStreamBodyProcessor{}
	})
	plugins.RegisterBodyProcessor("ndjson", func() plugintypes.BodyProcessor {
		return &jsonStreamBodyProcessor{}
	})
	plugins.RegisterBodyProcessor("jsonlines", func() plugintypes.BodyProcessor {
		return &jsonStreamBodyProcessor{}
	})
}
