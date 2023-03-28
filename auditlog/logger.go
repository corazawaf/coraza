// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"fmt"
	"io/fs"
	"strings"
)

// Config is the configuration of a Writer.
type Config struct {

	// Formatter is the formatter to use when writing formatted audit logs.
	Formatter Formatter
	// File is the path to the file to write the raw audit log to.
	File string

	// Dir is the path to the directory to write formatted audit logs to.
	Dir string

	// FileMode is the mode to use when creating File.
	FileMode fs.FileMode

	// DirMode is the mode to use when creating Dir.
	DirMode fs.FileMode
}

// NewConfig returns a Config with default values.
func NewConfig() Config {
	return Config{
		File:      "",
		FileMode:  0644,
		Dir:       "",
		DirMode:   0755,
		Formatter: nativeFormatter,
	}
}

// Formatter is the interface for all log formatters
// A Formatter receives an auditlog and generates "readable" audit log
type Formatter = func(al *Log) ([]byte, error)

// Writer is the interface for all log writers
// A Writer receives an auditlog and writes it to the output stream
// An output stream may be a file, a socket, an http request, etc
type Writer interface {
	// Init the writer requires previous preparations
	Init(Config) error
	// Write the audit log
	// Using the Formatter is mandatory to generate a "readable" audit log
	// It is not sent as a bslice because some writers may require some Audit
	// metadata.
	Write(*Log) error
	// Close the writer if required
	Close() error
}

type loggerWrapper = func() Writer

var writers = map[string]loggerWrapper{}
var formatters = map[string]Formatter{}

// RegisterWriter registers a new logger
// it can be used for plugins
func RegisterWriter(name string, writer func() Writer) {
	writers[name] = writer
}

// GetWriter returns a logger by name
// It returns an error if it doesn't exist
func GetWriter(name string) (Writer, error) {
	logger := writers[strings.ToLower(name)]
	if logger == nil {
		return nil, fmt.Errorf("invalid logger %q", name)
	}
	return logger(), nil
}

// RegisterFormatter registers a new logger format
// it can be used for plugins
func RegisterFormatter(name string, f func(al *Log) ([]byte, error)) {
	formatters[name] = f
}

// GetFormatter returns a formatter by name
// It returns an error if it doesn't exist
func GetFormatter(name string) (Formatter, error) {
	formatter := formatters[strings.ToLower(name)]
	if formatter == nil {
		return nil, fmt.Errorf("invalid formatter %q", name)
	}
	return formatter, nil
}
