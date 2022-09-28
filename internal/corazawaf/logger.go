// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"io"
	"log"

	"github.com/corazawaf/coraza/v3/loggers"
)

// DebugLogger is a logger that logs to the standard logger
type stdDebugLogger struct {
	logger *log.Logger
	Level  loggers.LogLevel
}

func (l *stdDebugLogger) formatLog(level loggers.LogLevel, message string, args ...interface{}) {
	if l.Level >= level {
		l.logger.Printf("[%s] %s", level.String(), fmt.Sprintf(message, args...))
	}
}

// Info logs an info message
func (l *stdDebugLogger) Info(message string, args ...interface{}) {
	l.formatLog(loggers.LogLevelInfo, message, args...)
}

// Warn logs a warning message
func (l *stdDebugLogger) Warn(message string, args ...interface{}) {
	l.formatLog(loggers.LogLevelWarn, message, args...)
}

// Error logs an error message
func (l *stdDebugLogger) Error(message string, args ...interface{}) {
	l.formatLog(loggers.LogLevelError, message, args...)
}

// Debug logs a debug message
func (l *stdDebugLogger) Debug(message string, args ...interface{}) {
	l.formatLog(loggers.LogLevelDebug, message, args...)
}

// Trace logs a trace message
func (l *stdDebugLogger) Trace(message string, args ...interface{}) {
	l.formatLog(loggers.LogLevelTrace, message, args...)
}

// SetLevel sets the log level
func (l *stdDebugLogger) SetLevel(level loggers.LogLevel) {
	if level.Invalid() {
		l.Info("Invalid log level, defaulting to INFO")
		level = loggers.LogLevelInfo
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
