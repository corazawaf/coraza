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

	"github.com/jptosso/coraza-waf/v2/utils"
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

func (l *Logger) Close() error {
	return l.writer.Close()
}

func (l *Logger) SetFormatter(f string) error {
	formatter, err := getLogFormatter(f)
	if err != nil {
		return err
	}
	l.formatter = formatter
	return nil
}

func (l *Logger) SetWriter(name string) error {
	writer, err := getLogWriter(name)
	if err != nil {
		return err
	}
	l.writer = writer
	return nil
}

type LogFormatter = func(al AuditLog) ([]byte, error)
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

// GetLogger returns a logger by name
// It returns an error if it doesn't exist
func getLogWriter(name string) (LogWriter, error) {
	logger := writers[name]
	if logger == nil {
		return nil, fmt.Errorf("invalid logger %q", name)
	}
	return logger(), nil
}

// RegisterLogFormat registers a new logger format
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
	s := &serialWriter{}
	f := path.Join(os.TempDir(), utils.RandomString(10)+"-coraza.log")
	l := &Logger{
		file:      f,
		directory: "/opt/coraza/var/log/audit/",
		dirMode:   dirMode,
		fileMode:  fileMode,
		formatter: nativeFormatter,
		writer:    s,
	}
	return l, s.Init(l)
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
	//RegisterLogFormatter("cef", cefFormatter)
}
