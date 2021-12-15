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
	"path/filepath"
)

// LoggerOptions contains all the information required by a Logger
// like where to store a log and the file permissions.
// Implementations may ignore the options.
type LoggerOptions struct {
	// DirMode is the file mode to assign to newly created directories
	DirMode fs.FileMode
	// FileMode is the mode to assign to newly created files
	FileMode fs.FileMode
	// File provides a unique path to some location like
	// /var/log/coraza/audit.log
	File string
	// Dir provides a unique path to write files, it's mostly
	// used for concurrent logging
	Dir string

	Formatter LogFormatter
}

// Logger is a wrapper to hold configurations, a writer and a formatter
// It is stored in the WAF Instance and used by the transactions
// It must be instanced by using NewLogger(...)
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
		return nil // we return nil because it is not an error, it is just not set
		// return fmt.Errorf("no audit log writer")
	}
	return l.writer.Write(al)
}

// Close is sed to close the write stream
// It must be called when the waf instance won't be used anymore
func (l *Logger) Close() error {
	if l.writer == nil {
		return fmt.Errorf("no writer to close")
	}
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
	return l.writer.Init(LoggerOptions{
		DirMode:   l.dirMode,
		FileMode:  l.fileMode,
		File:      l.file,
		Dir:       l.directory,
		Formatter: l.formatter,
	})
}

// SetFile sets the file for the logger
// The file path must exist and must be absolute
func (l *Logger) SetFile(file string) error {
	/*
		File can be a url
		if !filepath.IsAbs(file) {
			return fmt.Errorf("file path must be absolute")
		}
	*/

	l.file = file
	return nil
}

// SetDir sets the directory for the concurrent logger
// The directory must exist and must be absolute
func (l *Logger) SetDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("directory path must be absolute")
	}
	l.directory = dir
	return nil
}

// SetFileMode sets the file mode for the logger
func (l *Logger) SetFileMode(mode fs.FileMode) {
	l.fileMode = mode
}

// SetDirMode sets the directory mode for the logger
func (l *Logger) SetDirMode(mode fs.FileMode) {
	l.dirMode = mode
}

// LogFormatter is the interface for all log formatters
// A LogFormatter receives an auditlog and generates "readable" audit log
type LogFormatter = func(al AuditLog) ([]byte, error)

// LogWriter is the interface for all log writers
// A LogWriter receives an auditlog and writes it to the output stream
// An output stream may be a file, a socket, an http request, etc
type LogWriter interface {
	// In case the writer requires previous preparations
	Init(LoggerOptions) error
	// Writes the audit log using the Logger properties
	Write(AuditLog) error
	// Closes the writer if required
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
func NewAuditLogger() (*Logger, error) {
	dirMode := fs.FileMode(0755)
	fileMode := fs.FileMode(0644)
	l := &Logger{
		dirMode:  dirMode,
		fileMode: fileMode,
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
	RegisterLogFormatter("jsonlegacy", legacyJSONFormatter)
	RegisterLogFormatter("native", nativeFormatter)
}
