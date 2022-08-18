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

package coraza

import (
	"fmt"
	"io"
	"log"
)

// LogLevel is the type of log level
type LogLevel int

const (
	// LogLevelUnknown is a default value for unknown log level
	LogLevelUnknown LogLevel = iota
	// LogLevelInfo is the lowest level of logging
	LogLevelInfo
	// LogLevelWarn is the level of logging for warnings
	LogLevelWarn
	// LogLevelError is the level of logging for errors
	LogLevelError
	// LogLevelDebug is the level of logging for debug messages
	LogLevelDebug
	// LogLevelTrace is the highest level of logging
	LogLevelTrace
)

// String returns the string representation of the log level
func (level LogLevel) String() string {
	switch level {
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelTrace:
		return "TRACE"
	}
	return "UNKNOWN"
}

// Invalid returns true if the log level is invalid
func (level LogLevel) Invalid() bool {
	return level < LogLevelInfo || level > LogLevelTrace
}

// DebugLogger is used to log SecDebugLog messages
type DebugLogger interface {
	// Info logs an info message
	Info(message string, args ...interface{})
	// Warn logs a warning message
	Warn(message string, args ...interface{})
	// Error logs an error message
	Error(message string, args ...interface{})
	// Debug logs a debug message
	Debug(message string, args ...interface{})
	// Trace logs a trace message
	Trace(message string, args ...interface{})
	// SetLevel sets the log level
	SetLevel(level LogLevel)
	// SetOutput sets the output for the logger
	SetOutput(w io.Writer)
}

// DebugLogger is a logger that logs to the standard logger
type stdDebugLogger struct {
	logger *log.Logger
	Level  LogLevel
}

func (l *stdDebugLogger) formatLog(level LogLevel, message string, args ...interface{}) {
	if l.Level >= level {
		l.logger.Printf("[%s] %s", level.String(), fmt.Sprintf(message, args...))
	}
}

// Info logs an info message
func (l *stdDebugLogger) Info(message string, args ...interface{}) {
	l.formatLog(LogLevelInfo, message, args...)
}

// Warn logs a warning message
func (l *stdDebugLogger) Warn(message string, args ...interface{}) {
	l.formatLog(LogLevelWarn, message, args...)
}

// Error logs an error message
func (l *stdDebugLogger) Error(message string, args ...interface{}) {
	l.formatLog(LogLevelError, message, args...)
}

// Debug logs a debug message
func (l *stdDebugLogger) Debug(message string, args ...interface{}) {
	l.formatLog(LogLevelDebug, message, args...)
}

// Trace logs a trace message
func (l *stdDebugLogger) Trace(message string, args ...interface{}) {
	l.formatLog(LogLevelTrace, message, args...)
}

// SetLevel sets the log level
func (l *stdDebugLogger) SetLevel(level LogLevel) {
	if level.Invalid() {
		l.Info("Invalid log level, defaulting to INFO")
		level = LogLevelInfo
	}
	l.Level = level
}

// SetOutput sets the output for the logger
func (l *stdDebugLogger) SetOutput(w io.Writer) {
	l.logger.SetOutput(w)
}

// Close closes the logger
func (l *stdDebugLogger) Close() error {
	// TODO
	return nil
}
