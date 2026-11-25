// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
)

type defaultEvent struct {
	level   Level
	printer Printer
	fields  []byte
}

func (e *defaultEvent) Msg(msg string) {
	if len(msg) == 0 {
		return
	}

	if len(e.fields) == 0 {
		e.printer(e.level, msg, "")
	} else {
		// if event has fields, there serialization starts with a
		// trailing space.
		e.printer(e.level, msg, string(e.fields[1:]))
	}
}

func (e *defaultEvent) Str(key, val string) Event {
	e.fields = append(e.fields, ' ')
	e.fields = append(e.fields, key...)
	e.fields = append(e.fields, '=')
	e.fields = append(e.fields, strconv.Quote(val)...)

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
	return e.Str(key, val.String())
}

func (defaultEvent) IsEnabled() bool {
	return true
}

type defaultLogger struct {
	printer       Printer
	factory       PrinterFactory
	level         Level
	defaultFields []byte
}

func (l defaultLogger) WithOutput(w io.Writer) Logger {
	return defaultLogger{
		printer:       l.factory(w),
		factory:       l.factory,
		level:         l.level,
		defaultFields: l.defaultFields,
	}
}

func (l defaultLogger) WithLevel(lvl Level) Logger {
	return defaultLogger{
		printer:       l.printer,
		factory:       l.factory,
		level:         lvl,
		defaultFields: l.defaultFields,
	}
}

func (l defaultLogger) With(fs ...ContextField) Logger {
	// Each field gets the Event the previous one returned, as in a chain of
	// Event calls, so a wrapper that overrides Str applies to the fields after
	// it for as long as they return it. A field returning nil or a disabled
	// Event, such as a no-op one, leaves the current Event in place, so the
	// fields after it are kept. The fields come from the last *defaultEvent
	// returned. Asserting the last Event to *defaultEvent panicked when a
	// field returned anything else.
	last := &defaultEvent{}
	var cur Event = last
	for _, f := range fs {
		next := f(cur)
		if next == nil || !next.IsEnabled() {
			continue
		}
		cur = next
		if d, ok := next.(*defaultEvent); ok {
			last = d
		}
	}
	return defaultLogger{
		printer:       l.printer,
		factory:       l.factory,
		level:         l.level,
		defaultFields: append(l.defaultFields, last.fields...),
	}
}

func (l defaultLogger) Trace() Event {
	if l.level < LevelTrace {
		return noopEvent{}
	}

	return &defaultEvent{printer: l.printer, level: LevelTrace, fields: l.defaultFields}
}

func (l defaultLogger) Debug() Event {
	if l.level < LevelDebug {
		return noopEvent{}
	}

	return &defaultEvent{printer: l.printer, level: LevelDebug, fields: l.defaultFields}
}

func (l defaultLogger) Info() Event {
	if l.level < LevelInfo {
		return noopEvent{}
	}

	return &defaultEvent{printer: l.printer, level: LevelInfo, fields: l.defaultFields}
}

func (l defaultLogger) Warn() Event {
	if l.level < LevelWarn {
		return noopEvent{}
	}

	return &defaultEvent{printer: l.printer, level: LevelWarn, fields: l.defaultFields}
}

func (l defaultLogger) Error() Event {
	if l.level < LevelError {
		return noopEvent{}
	}

	return &defaultEvent{printer: l.printer, level: LevelError, fields: l.defaultFields}
}

// Default returns a default logger that writes to stderr.
func Default() Logger {
	return DefaultWithPrinterFactory(defaultPrinterFactory)
}

type Printer func(lvl Level, message, fields string)

type PrinterFactory func(w io.Writer) Printer

var defaultPrinterFactory = func(w io.Writer) Printer {
	l := log.New(w, "", log.LstdFlags)
	return func(lvl Level, message, fields string) {
		l.Printf("[%s] %s %s", lvl.String(), message, fields)
	}
}

// DefaultWithPrinterFactory returns a default logger that writes to stderr with a given
// printer factory. It is useful when you need to abstract the printer.
func DefaultWithPrinterFactory(f PrinterFactory) Logger {
	return defaultLogger{
		printer: f(os.Stderr),
		factory: f,
		level:   LevelInfo,
	}
}
