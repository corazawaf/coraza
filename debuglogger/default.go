// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglogger

import (
	"fmt"
	"io"
	"log"
	"strconv"
)

type defaultEvent struct {
	level  LogLevel
	logger *log.Logger
	fields []byte
}

func (e *defaultEvent) Msg(msg string) {
	if len(msg) == 0 {
		return
	}

	e.logger.Print("[", e.level.String(), "] ", msg, string(e.fields))
}

func (e *defaultEvent) Str(key, val string) Event {
	e.fields = append(e.fields, ' ')
	e.fields = append(e.fields, key...)
	e.fields = append(e.fields, '=')
	e.fields = append(e.fields, val...)
	return e
}

func (e *defaultEvent) Err(err error) Event {
	if err == nil {
		return e
	}

	e.fields = append(e.fields, " error=\""...)
	e.fields = append(e.fields, err.Error()...)
	e.fields = append(e.fields, '"')
	return e
}

func (e *defaultEvent) Bool(key string, b bool) Event {
	e.fields = append(e.fields, ' ')
	e.fields = append(e.fields, key...)
	e.fields = append(e.fields, '=')
	if b {
		e.fields = append(e.fields, "true"...)
	} else {
		e.fields = append(e.fields, "false"...)
	}
	return e
}

func (e *defaultEvent) Int(key string, i int) Event {
	e.fields = append(e.fields, ' ')
	e.fields = append(e.fields, key...)
	e.fields = append(e.fields, '=')
	e.fields = append(e.fields, strconv.Itoa(i)...)
	return e
}

func (e *defaultEvent) Uint(key string, i uint) Event {
	e.fields = append(e.fields, ' ')
	e.fields = append(e.fields, key...)
	e.fields = append(e.fields, '=')
	e.fields = append(e.fields, strconv.Itoa(int(i))...)
	return e
}

func (e *defaultEvent) Stringer(key string, val fmt.Stringer) Event {
	e.fields = append(e.fields, ' ')
	e.fields = append(e.fields, key...)
	e.fields = append(e.fields, '=')
	e.fields = append(e.fields, val.String()...)
	return e
}

type defaultLogger struct {
	*log.Logger
	level LogLevel
}

func (l defaultLogger) WithOutput(w io.Writer) Logger {
	if l.Logger == nil {
		return defaultLogger{
			Logger: log.New(w, "", log.LstdFlags),
			level:  l.level,
		}
	}

	return defaultLogger{
		Logger: log.New(w, l.Logger.Prefix(), l.Logger.Flags()),
		level:  l.level,
	}
}

func (l defaultLogger) WithLevel(lvl LogLevel) Logger {
	return defaultLogger{Logger: l.Logger, level: lvl}
}

func (l defaultLogger) Trace() Event {
	if l.level < LogLevelTrace {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func (l defaultLogger) Debug() Event {
	if l.level < LogLevelDebug {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func (l defaultLogger) Info() Event {
	if l.level < LogLevelInfo {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func (l defaultLogger) Warn() Event {
	if l.level < LogLevelWarn {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

func (l defaultLogger) Error() Event {
	if l.level < LogLevelError {
		return NopEvent{}
	}

	return &defaultEvent{logger: l.Logger, level: LogLevelError}
}

// Default returns a default logger that writes to stderr.
func Default() Logger {
	return defaultLogger{
		Logger: log.Default(),
		level:  LogLevelInfo,
	}
}
