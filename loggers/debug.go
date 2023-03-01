// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package loggers

import (
	"fmt"
	"io"
)

type Event interface {
	// Msg sends the Event with msg added as the message field if not empty.
	Msg(msg string)
	// Str adds the field key with val as a string to the Event.
	Str(key, val string) Event
	// Err adds the field "error" with serialized err to the Event.
	// If err is nil, no field is added.
	Err(err error) Event
	// Bool adds the field key with val as a bool to the Event.
	Bool(key string, b bool) Event
	// Int adds the field key with i as a int to the Event.
	Int(key string, i int) Event
	// Uint adds the field key with i as a uint to the Event.
	Uint(key string, i uint) Event
	// Stringer adds the field key with val.String() (or null if val is nil)
	// to the Event.
	Stringer(key string, val fmt.Stringer) Event
}

type NopEvent struct{}

func (NopEvent) Msg(msg string)                                {}
func (e NopEvent) Str(key, val string) Event                   { return e }
func (e NopEvent) Err(err error) Event                         { return e }
func (e NopEvent) Bool(key string, b bool) Event               { return e }
func (e NopEvent) Int(key string, i int) Event                 { return e }
func (e NopEvent) Uint(key string, i uint) Event               { return e }
func (e NopEvent) Stringer(key string, val fmt.Stringer) Event { return e }

// DebugLogger is used to log SecDebugLog messages
type DebugLogger interface {
	WithOutput(w io.Writer) DebugLogger
	WithLevel(lvl LogLevel) DebugLogger
	Trace() Event
	Debug() Event
	Info() Event
	Warn() Event
	Error() Event
}

func Nop() DebugLogger {
	return defaultLogger{level: LogLevelNoLog}
}

// LogLevel is the type of log level
type LogLevel int8

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
