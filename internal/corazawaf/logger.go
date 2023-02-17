// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"io"

	"github.com/rs/zerolog"

	"github.com/corazawaf/coraza/v3/loggers"
)

// DebugLogger is a logger that logs to the standard logger
type stdDebugLogger struct {
	io.Closer
	logger *zerolog.Logger
	Level  loggers.LogLevel
}

var _ loggers.DebugLogger = (*stdDebugLogger)(nil)

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
	zerolog.SetGlobalLevel(getZeroLogLevel(level))
}

// SetOutput sets the output for the logger
func (l *stdDebugLogger) SetOutput(w io.WriteCloser) {
	if l.Closer != nil {
		l.Closer.Close()
	}
	updateLogger := l.logger.Output(w)
	l.logger = &updateLogger
	l.Closer = w
}

func (l *stdDebugLogger) GetLogger() *zerolog.Logger {
	return l.logger
}

func (l *stdDebugLogger) Writer() io.Writer {
	return *(l.logger)
}

func getZeroLogLevel(level loggers.LogLevel) zerolog.Level {
	switch level {
	case loggers.LogLevelNoLog:
		return zerolog.NoLevel
	case loggers.LogLevelError:
		return zerolog.ErrorLevel
	case loggers.LogLevelWarn:
		return zerolog.WarnLevel
	case loggers.LogLevelInfo:
		return zerolog.InfoLevel
	case loggers.LogLevelDebug:
		return zerolog.DebugLevel
	case loggers.LogLevelTrace:
		return zerolog.TraceLevel
	default:
		return zerolog.InfoLevel
	}
}
