// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package loggers

import (
	"io"
)

// DebugLogger is used to log SecDebugLog messages
type DebugLogger interface {
	// Error logs an error message
	Error(message string, args ...interface{})
	// Warn logs a warning message
	Warn(message string, args ...interface{})
	// Info logs an info message
	Info(message string, args ...interface{})
	// Debug logs a debug message
	Debug(message string, args ...interface{})
	// Trace logs a trace message
	Trace(message string, args ...interface{})
	// SetLevel sets the log level
	SetLevel(level LogLevel)
	// SetOutput sets the output for the logger and closes
	// the former output if any.
	SetOutput(w io.WriteCloser)
}

// LogLevel is the type of log level
type LogLevel int

const (
	// LogLevelUnknown is a default value for unknown log level
	LogLevelUnknown LogLevel = iota - 1
	// LogLevelNoLog is the lowest level of logging, no logs are generated
	LogLevelNoLog
	// LogLevelError is the level of logging only for errors
	LogLevelError
	// LogLevelWarn is the level of logging for warnings
	LogLevelWarn
	// LogLevelInfo is the lowest of logging for informational messages
	LogLevelInfo
	// LogLevelDebug is the level of logging for debug messages
	LogLevelDebug
	// ModSecurity compatibility, levels 4-8 will be Debug level
	_ = iota + 2
	// LogLevelTrace is the highest level of logging
	LogLevelTrace
)

// String returns the string representation of the log level
func (level LogLevel) String() string {
	switch {
	case level == LogLevelNoLog:
		return "NOLOG"
	case level == LogLevelError:
		return "ERROR"
	case level == LogLevelWarn:
		return "WARN"
	case level == LogLevelInfo:
		return "INFO"
	case level >= LogLevelDebug && level < LogLevelTrace:
		return "DEBUG"
	case level == LogLevelTrace:
		return "TRACE"
	}
	return "UNKNOWN"
}

// Invalid returns true if the log level is invalid
func (level LogLevel) Invalid() bool {
	return level < LogLevelNoLog || level > LogLevelTrace
}
