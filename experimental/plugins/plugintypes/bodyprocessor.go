// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

import (
	"io"
	"io/fs"
)

// BodyProcessorOptions are used by BodyProcessors to provide some settings
// like a path to store temporary files.
// Implementations may ignore the options.
type BodyProcessorOptions struct {
	// Mime is the type of the body, it may contain parameters
	// like charset, boundary, etc.
	Mime string
	// StoragePath is the path where the body will be stored
	StoragePath string
	// FileMode is the mode of the file that will be created
	FileMode fs.FileMode
	// DirMode is the mode of the directory that will be created
	DirMode fs.FileMode
	// RequestBodyRecursionLimit is the maximum recursion level accepted in a body processor
	RequestBodyRecursionLimit int
}

// BodyProcessor interface is used to create
// body processors for different content-types.
// They are able to read the body, force a collection.
// Hook to some variable and return data based on special
// expressions like XPATH, JQ, etc.
type BodyProcessor interface {
	ProcessRequest(reader io.Reader, variables TransactionVariables, options BodyProcessorOptions) error
	ProcessResponse(reader io.Reader, variables TransactionVariables, options BodyProcessorOptions) error
}

// Record represents a single parsed record from a streaming body processor.
// A record can be anything the format defines as a discrete unit: a JSON object,
// a CSV row, a protobuf message, a log line, etc.
//
// Implementations are provided by each [StreamingBodyProcessor] and are
// format-specific.
type Record interface {
	// Fields returns the record's data flattened into string key-value pairs
	// suitable for populating WAF variables (ArgsPost, ResponseArgs).
	//
	// Keys should include a processor-specific prefix with the record number
	// (e.g., "json.0.user.name", "csv.3.email"). Values are the string
	// representation of each field — the body processor is responsible for
	// serializing its native types (numbers, booleans, nested structures,
	// binary blobs) into strings.
	Fields() map[string]string

	// Raw returns the original record bytes including any format-specific
	// framing (e.g., trailing newline for NDJSON, RS prefix for RFC 7464,
	// length-prefixed envelope for protobuf streams). The returned slice
	// is used by the relay path to forward records verbatim to the backend.
	Raw() []byte
}

// StreamingBodyProcessor extends BodyProcessor with per-record streaming support.
// Body processors that handle multi-record formats (e.g., NDJSON, JSON-Seq, CSV,
// length-prefixed protobuf streams) can implement this interface to enable
// per-record rule evaluation instead of evaluating rules only after the entire
// body has been consumed.
//
// The callback receives a [Record] for each parsed entry and its zero-based index.
// Returning a non-nil error from the callback stops processing immediately.
//
// # Concurrency
//
// The callback executes synchronously on the caller's goroutine — the same
// goroutine that called ProcessRequestRecords or ProcessResponseRecords. The
// callback must not be called from multiple goroutines, and the body processor
// must not read ahead into a separate goroutine while the callback is running.
//
// If rule evaluation in the callback takes significant time, the body processor's
// read loop will naturally slow down, applying backpressure to the sender via
// TCP flow control. This is desirable for DoS protection.
type StreamingBodyProcessor interface {
	BodyProcessor

	// ProcessRequestRecords reads records one at a time from the reader and calls fn
	// for each record. Processing stops if fn returns a non-nil error.
	ProcessRequestRecords(reader io.Reader, options BodyProcessorOptions,
		fn func(recordNum int, record Record) error) error

	// ProcessResponseRecords is the response equivalent of ProcessRequestRecords.
	ProcessResponseRecords(reader io.Reader, options BodyProcessorOptions,
		fn func(recordNum int, record Record) error) error
}
