// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

// Level is the type of log level
type Level int8

const (
	// LevelUnknown is a default value for unknown log level
	LevelUnknown Level = iota - 1
	// LevelNoLog is the lowest level of logging, no logs are generated
	LevelNoLog
	// LevelError is the level of logging only for errors
	LevelError
	// LevelWarn is the level of logging for warnings
	LevelWarn
	// LevelInfo is the lowest of logging for informational messages
	LevelInfo
	// LevelDebug is the level of logging for debug messages
	LevelDebug
	// ModSecurity compatibility, levels 4-8 will be Debug level
	_ = iota + 2
	// LevelTrace is the highest level of logging
	LevelTrace
)

// String returns the string representation of the log level
func (level Level) String() string {
	switch {
	case level == LevelNoLog:
		return "NOLOG"
	case level == LevelError:
		return "ERROR"
	case level == LevelWarn:
		return "WARN"
	case level == LevelInfo:
		return "INFO"
	case level >= LevelDebug && level < LevelTrace:
		return "DEBUG"
	case level == LevelTrace:
		return "TRACE"
	}
	return "UNKNOWN"
}

// Valid returns true if the log level is valid
func (level Level) Valid() bool {
	return level >= LevelNoLog && level <= LevelTrace
}
