// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglogger

import (
	"fmt"
	"io"
)

// Event represents a log event. It is instanced by one of the level method of
// Logger and finalized by the Msg  method.
type Event interface {
	// Msg sends the Event with msg added as the message field if not empty.
	Msg(msg string)
	// Str adds the field key with val as a string to the Event.
	Str(key, val string) Event
	// Err adds the field "error" with serialized err to the Event.
	// If err is nil, no field is added.
	Err(err error) Event
	// Errs adds the field "error" with a serialized array of err to the Event.
	Errs(errs ...error) Event
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

type ContextField func(Event) Event

func Str(key, val string) ContextField {
	return func(e Event) Event {
		return e.Str(key, val)
	}
}

func Bool(key string, b bool) ContextField {
	return func(e Event) Event {
		return e.Bool(key, b)
	}
}

func Int(key string, i int) ContextField {
	return func(e Event) Event {
		return e.Int(key, i)
	}
}

func Uint(key string, i uint) ContextField {
	return func(e Event) Event {
		return e.Uint(key, i)
	}
}

func Stringer(key string, val fmt.Stringer) ContextField {
	return func(e Event) Event {
		return e.Stringer(key, val)
	}
}

// Logger is used to log SecDebugLog messages
// This interface is highly inspired in github.com/rs/zerolog logger and the aim
// is to avoid allocations while logging.
type Logger interface {
	// WithOutput duplicates the current logger and sets w as its output.
	WithOutput(w io.Writer) Logger

	// Level creates a child logger with the minimum accepted level set to level.
	WithLevel(lvl LogLevel) Logger

	// WithOutput duplicates the current logger and adds context fields to it.
	With(...ContextField) Logger

	// Trace starts a new message with trace level.
	// You must call Msg on the returned event in order to send the event.
	Trace() Event

	// Debug starts a new message with debug level.
	// You must call Msg on the returned event in order to send the event.
	Debug() Event

	// Info starts a new message with info level.
	// You must call Msg on the returned event in order to send the event.
	Info() Event

	// Warn starts a new message with warn level.
	// You must call Msg on the returned event in order to send the event.
	Warn() Event

	// Error starts a new message with error level.
	// You must call Msg on the returned event in order to send the event.
	Error() Event
}
