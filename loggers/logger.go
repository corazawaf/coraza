// Copyright 2021 Juan Pablo Tosso
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
	"io/fs"
	"os"
	"path"
)

// Logger is a wrapper to hold configurations, a writer and a formatter
// It is stored in the WAF Instance and used by the transactions
// It must be instanced by using NewLogger(...)
// TODO maybe we should not export it
type Logger struct {
	file      string
	directory string
	dirMode   fs.FileMode
	fileMode  fs.FileMode
	formatter LogFormatter
	writer    LogWriter
}

// Write is used by the transactions to write to the audit log writer
// Important: Concurrency must be handled by the writer, not the logger
func (l Logger) Write(al AuditLog) error {
	if l.writer == nil {
		return fmt.Errorf("no audit log writer")
	}
	return l.writer.Write(al)
}

// Close is sed to close the write stream
// It must be called when the waf instance won't be used anymore
func (l *Logger) Close() error {
	return l.writer.Close()
}

// SetFormatter sets the formatter for the logger
// A valid formatter created using RegisterLogFormatter(...) is required
// Default formatters are: json, json2 and native
// json2 is an "enhanced" version of the original modsecurity json formatter
func (l *Logger) SetFormatter(f string) error {
	formatter, err := getLogFormatter(f)
	if err != nil {
		return err
	}
	l.formatter = formatter
	return nil
}

// SetWriter sets the writer for the logger
// A valid writer created using RegisterLogWriter(...) is required
// Default writers are: serial and concurrent
func (l *Logger) SetWriter(name string) error {
	writer, err := getLogWriter(name)
	if err != nil {
		return err
	}
	l.writer = writer
	return l.writer.Init(l)
}

// LogFormatter is the interface for all log formatters
// A LogFormatter receives an auditlog and generates "readable" audit log
type LogFormatter = func(al AuditLog) ([]byte, error)

// LogWriter is the interface for all log writers
// A LogWriter receives an auditlog and writes it to the output stream
// An output stream may be a file, a socket, an http request, etc
type LogWriter interface {
	// In case the writer requires previous preparations
	Init(*Logger) error
	// Writes the audit log using the Logger properties
	Write(AuditLog) error
	// Closes the writer if required
	Close() error
}

type loggerWrapper = func() LogWriter

var writers = map[string]loggerWrapper{}
var formatters = map[string]LogFormatter{}

// RegisterLogger registers a new logger
// it can be used for plugins
func RegisterLogWriter(name string, writer func() LogWriter) {
	writers[name] = writer
}

// getLogWriter returns a logger by name
// It returns an error if it doesn't exist
func getLogWriter(name string) (LogWriter, error) {
	logger := writers[name]
	if logger == nil {
		return nil, fmt.Errorf("invalid logger %q", name)
	}
	return logger(), nil
}

// RegisterLogFormatter registers a new logger format
// it can be used for plugins
func RegisterLogFormatter(name string, f func(al AuditLog) ([]byte, error)) {
	formatters[name] = f
}

// getLogFormatter returns a formatter by name
// It returns an error if it doesn't exist
func getLogFormatter(name string) (LogFormatter, error) {
	formatter := formatters[name]
	if formatter == nil {
		return nil, fmt.Errorf("invalid formatter %q", name)
	}
	return formatter, nil
}

// NewAuditLogger creates a default logger
// Default settings are:
// Dirmode: 0755
// Filemode: 0644
// Formatter: native
// Writer: serial
// Path: /tmp/coraza-audit.log
func NewAuditLogger() (*Logger, error) {
	/*
		if file == "" {
			return nil, fmt.Errorf("invalid file")
		}
		if directory == "" {
			return nil, fmt.Errorf("invalid directory")
		}*/
	dirMode := fs.FileMode(0755)
	fileMode := fs.FileMode(0644)
	f := path.Join(os.TempDir(), "coraza-audit.log")
	l := &Logger{
		file:      f,
		directory: "/opt/coraza/var/log/audit/",
		dirMode:   dirMode,
		fileMode:  fileMode,
	}
	if err := l.SetWriter("serial"); err != nil {
		return nil, err
	}
	if err := l.SetFormatter("native"); err != nil {
		return nil, err
	}
	return l, nil
}

func init() {
	RegisterLogWriter("concurrent", func() LogWriter {
		return &concurrentWriter{}
	})
	RegisterLogWriter("serial", func() LogWriter {
		return &serialWriter{}
	})

	RegisterLogFormatter("json", jsonFormatter)
	RegisterLogFormatter("json2", json2Formatter)
	RegisterLogFormatter("native", nativeFormatter)
	// RegisterLogFormatter("cef", cefFormatter)
}
