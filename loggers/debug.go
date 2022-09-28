// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package loggers

import (
	"io"
)

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
