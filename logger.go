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

type LogLevel int

const (
	LogLevelUnknown LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelDebug
	LogLevelTrace
)

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

func (level LogLevel) Invalid() bool {
	return level < LogLevelInfo || level > LogLevelTrace
}

type DebugLogger struct {
	logger *log.Logger
	Level  LogLevel
}

func (l *DebugLogger) formatLog(level LogLevel, message string, args ...interface{}) {
	if l.Level >= level {
		l.logger.Printf("[%s] %s", level.String(), fmt.Sprintf(message, args...))
	}
}

func (l *DebugLogger) Info(message string, args ...interface{}) {
	l.formatLog(LogLevelInfo, message, args...)
}

func (l *DebugLogger) Warn(message string, args ...interface{}) {
	l.formatLog(LogLevelWarn, message, args...)
}

func (l *DebugLogger) Error(message string, args ...interface{}) {
	l.formatLog(LogLevelError, message, args...)
}

func (l *DebugLogger) Debug(message string, args ...interface{}) {
	l.formatLog(LogLevelDebug, message, args...)
}

func (l *DebugLogger) Trace(message string, args ...interface{}) {
	l.formatLog(LogLevelTrace, message, args...)
}

func (l *DebugLogger) SetLevel(level LogLevel) {
	if level.Invalid() {
		l.Info("Invalid log level, defaulting to INFO")
		level = LogLevelInfo
	}
	l.Level = level
}

func (l *DebugLogger) SetOutput(w io.Writer) {
	l.logger.SetOutput(w)
}

func (l *DebugLogger) Close() error {
	// TODO
	return nil
}
