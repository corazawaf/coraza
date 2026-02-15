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

// StreamingBodyProcessor extends BodyProcessor with per-record streaming support.
// Body processors that handle multi-record formats (NDJSON, JSON-Seq) can implement
// this interface to enable per-record rule evaluation instead of evaluating rules
// only after the entire body has been consumed.
//
// The callback receives pre-formatted field keys including the record number prefix
// (e.g., "json.0.name", "json.1.age") and the raw record text. Returning a non-nil
// error from the callback stops processing immediately.
type StreamingBodyProcessor interface {
	BodyProcessor

	// ProcessRequestRecords reads records one at a time from the reader and calls fn
	// for each record's parsed fields. Processing stops if fn returns a non-nil error.
	ProcessRequestRecords(reader io.Reader, options BodyProcessorOptions,
		fn func(recordNum int, fields map[string]string, rawRecord string) error) error

	// ProcessResponseRecords is the response equivalent of ProcessRequestRecords.
	ProcessResponseRecords(reader io.Reader, options BodyProcessorOptions,
		fn func(recordNum int, fields map[string]string, rawRecord string) error) error
}
