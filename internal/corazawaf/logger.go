// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run ./logger/generator/main.go

package corazawaf

import (
	"io"
	"log"

	"github.com/corazawaf/coraza/v3/internal/corazawaf/internal/logger"
	"github.com/corazawaf/coraza/v3/loggers"
)

type stdDebugLogger struct {
	io.Closer
	logger.DelegateLogger
	l *log.Logger
}

var _ loggers.DebugLogger = (*stdDebugLogger)(nil)

func newStdDebugLogger() loggers.DebugLogger {
	l := &log.Logger{}
	return &stdDebugLogger{
		DelegateLogger: logger.CreateLogger(int(loggers.LogLevelInfo), l),
		l:              l,
	}
}

// SetLevel sets the log level
func (l *stdDebugLogger) SetLevel(level loggers.LogLevel) {
	if level.Invalid() {
		l.DelegateLogger = logger.CreateLogger(int(loggers.LogLevelInfo), l.l)
		l.Info("Invalid log level, defaulting to INFO")
		return
	}
	l.DelegateLogger = logger.CreateLogger(int(level), l.l)
}

// SetOutput sets the output for the logger
func (l *stdDebugLogger) SetOutput(w io.WriteCloser) {
	if l.Closer != nil {
		l.Closer.Close()
	}
	l.DelegateLogger.SetOutput(w)
	l.Closer = w
}
