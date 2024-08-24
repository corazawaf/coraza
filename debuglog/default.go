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
	closable      io.Closer
}

func (l defaultLogger) WithOutput(w io.Writer) Logger {
	var closable io.Closer = nil
	// I kept w as io.Writer to keep compability and easy use
	if c, ok := w.(io.Closer); ok && w != os.Stdout && w != os.Stderr {
		closable = c
	}

	return defaultLogger{
		printer:       l.factory(w),
		factory:       l.factory,
		level:         l.level,
		defaultFields: l.defaultFields,
		closable:      closable,
	}
}

func (l defaultLogger) WithLevel(lvl Level) Logger {
	return defaultLogger{
		printer:       l.printer,
		factory:       l.factory,
		level:         lvl,
		defaultFields: l.defaultFields,
		closable:      l.closable,
	}
}

func (l defaultLogger) With(fs ...ContextField) Logger {
	var e Event = &defaultEvent{}
	for _, f := range fs {
		e = f(e)
	}
	return defaultLogger{
		printer:       l.printer,
		factory:       l.factory,
		level:         l.level,
		defaultFields: append(l.defaultFields, e.(*defaultEvent).fields...),
		closable:      l.closable,
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

func (l defaultLogger) Close() error {
	if l.closable != nil {
		return l.closable.Close()
	}
	return nil
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
