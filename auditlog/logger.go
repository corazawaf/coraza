// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"fmt"
	"io/fs"
	"strings"
)

// Config is the configuration of a LogWriter.
type Config struct {
	// File is the path to the file to write the raw audit log to.
	File string

	// FileMode is the mode to use when creating File.
	FileMode fs.FileMode

	// Dir is the path to the directory to write formatted audit logs to.
	Dir string

	// DirMode is the mode to use when creating Dir.
	DirMode fs.FileMode

	// Formatter is the formatter to use when writing formatted audit logs.
	Formatter LogFormatter
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

// LogFormatter is the interface for all log formatters
// A LogFormatter receives an auditlog and generates "readable" audit log
type LogFormatter = func(al *Log) ([]byte, error)

// LogWriter is the interface for all log writers
// A LogWriter receives an auditlog and writes it to the output stream
// An output stream may be a file, a socket, an http request, etc
type LogWriter interface {
	// Init the writer requires previous preparations
	Init(Config) error
	// Write the audit log
	// Using the LogFormatter is mandatory to generate a "readable" audit log
	// It is not sent as a bslice because some writers may require some Audit
	// metadata.
	Write(*Log) error
	// Close the writer if required
	Close() error
}

type loggerWrapper = func() LogWriter

var writers = map[string]loggerWrapper{}
var formatters = map[string]LogFormatter{}

// RegisterLogWriter registers a new logger
// it can be used for plugins
func RegisterLogWriter(name string, writer func() LogWriter) {
	writers[name] = writer
}

// GetLogWriter returns a logger by name
// It returns an error if it doesn't exist
func GetLogWriter(name string) (LogWriter, error) {
	logger := writers[strings.ToLower(name)]
	if logger == nil {
		return nil, fmt.Errorf("invalid logger %q", name)
	}
	return logger(), nil
}

// RegisterLogFormatter registers a new logger format
// it can be used for plugins
func RegisterLogFormatter(name string, f func(al *Log) ([]byte, error)) {
	formatters[name] = f
}

// GetLogFormatter returns a formatter by name
// It returns an error if it doesn't exist
func GetLogFormatter(name string) (LogFormatter, error) {
	formatter := formatters[strings.ToLower(name)]
	if formatter == nil {
		return nil, fmt.Errorf("invalid formatter %q", name)
	}
	return formatter, nil
}
