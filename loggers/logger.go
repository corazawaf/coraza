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
)

type Logger struct {
	File      string
	Directory string
	DirMode   fs.FileMode
	FileMode  fs.FileMode
	formatter LogFormatter
	writer    LogWriter
}

// Write is used by the transactions to write to the audit log writer
// Important: Concurrency must be handled by the writer, not the logger
func (l Logger) Write(al AuditLog) error {
	data, err := l.formatter(al)
	if err != nil {
		return err
	}
	return l.writer.Write(l, data)
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
	Init() error
	// Writes the audit log using the Logger properties
	Write(Logger, []byte) error
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

func NewLogger(file, directory string, dirMode, fileMode fs.FileMode) (Logger, error) {
	/*
		if file == "" {
			return nil, fmt.Errorf("invalid file")
		}
		if directory == "" {
			return nil, fmt.Errorf("invalid directory")
		}*/
	if dirMode == 0 {
		dirMode = fs.FileMode(0755)
	}
	if fileMode == 0 {
		fileMode = fs.FileMode(0644)
	}
	return Logger{
		File:      file,
		Directory: directory,
		DirMode:   dirMode,
		FileMode:  fileMode,
		formatter: nativeFormatter,
		writer:    serialWriter,
	}, nil
}

func init() {
	RegisterLogWriter("concurrent", func() LogWriter {
		return ConcurrentLogger{}
	})

	RegisterLogFormatter("json", jsonFormatter)
	RegisterLogFormatter("native", nativeFormatter)
	//RegisterLogFormatter("cef", cefFormatter)
}
