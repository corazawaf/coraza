// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"io"
	"log"

	"github.com/corazawaf/coraza/v3/debug"
)

// DebugLogger is a logger that logs to the standard logger
type stdDebugLogger struct {
	io.Closer
	logger *log.Logger
	Level  debug.Level
}

var _ debug.Logger = (*stdDebugLogger)(nil)

func (l *stdDebugLogger) formatLog(level debug.Level, message string, args ...interface{}) {
	if l.Level >= level {
		l.logger.Printf("[%s] %s", level.String(), fmt.Sprintf(message, args...))
	}
}

// Info logs an info message
func (l *stdDebugLogger) Info(message string, args ...interface{}) {
	l.formatLog(debug.LevelInfo, message, args...)
}

// Warn logs a warning message
func (l *stdDebugLogger) Warn(message string, args ...interface{}) {
	l.formatLog(debug.LevelWarn, message, args...)
}

// Error logs an error message
func (l *stdDebugLogger) Error(message string, args ...interface{}) {
	l.formatLog(debug.LevelError, message, args...)
}

// Debug logs a debug message
func (l *stdDebugLogger) Debug(message string, args ...interface{}) {
	l.formatLog(debug.LevelDebug, message, args...)
}

// Trace logs a trace message
func (l *stdDebugLogger) Trace(message string, args ...interface{}) {
	l.formatLog(debug.LevelTrace, message, args...)
}

// SetLevel sets the log level
func (l *stdDebugLogger) SetLevel(level debug.Level) {
	if level.Invalid() {
		l.Info("Invalid log level, defaulting to INFO")
		level = debug.LevelInfo
	}
	l.Level = level
}

// SetOutput sets the output for the logger
func (l *stdDebugLogger) SetOutput(w io.WriteCloser) {
	if l.Closer != nil {
		l.Closer.Close()
	}
	l.logger.SetOutput(w)
	l.Closer = w
}
