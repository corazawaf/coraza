// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loggers

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v2/types"
)

// LogFormatter is the interface for all log formatters
// A LogFormatter receives an auditlog and generates "readable" audit log
type LogFormatter = func(al *AuditLog) ([]byte, error)

// LogWriter is the interface for all log writers
// A LogWriter receives an auditlog and writes it to the output stream
// An output stream may be a file, a socket, an http request, etc
type LogWriter interface {
	// Init the writer requires previous preparations
	Init(types.WafConfig) error
	// Write the audit log
	// Using the LogFormatter is mandatory to generate a "readable" audit log
	// It is not sent as a bslice because some writers may require some Audit
	// metadata.
	Write(*AuditLog) error
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
func RegisterLogFormatter(name string, f func(al *AuditLog) ([]byte, error)) {
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

func init() {
	RegisterLogWriter("concurrent", func() LogWriter {
		return &concurrentWriter{}
	})
	RegisterLogWriter("serial", func() LogWriter {
		return &serialWriter{}
	})

	RegisterLogFormatter("json", jsonFormatter)
	RegisterLogFormatter("jsonlegacy", legacyJSONFormatter)
	RegisterLogFormatter("native", nativeFormatter)
}
