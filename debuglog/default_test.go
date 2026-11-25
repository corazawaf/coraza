// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// prefixEvent is an integrator-style Event wrapper that renames the keys of the
// string fields written through it.
type prefixEvent struct{ Event }

func (p prefixEvent) Str(key, val string) Event { return p.Event.Str("p."+key, val) }

func TestLoggerLogLevels(t *testing.T) {
	testCases := map[string]struct {
		logFunction                func(Logger) func() Event
		expectedLowestPrintedLevel int
	}{
		"Trace": {
			logFunction:                func(l Logger) func() Event { return l.Trace },
			expectedLowestPrintedLevel: 9,
		},
		"Debug": {
			logFunction:                func(l Logger) func() Event { return l.Debug },
			expectedLowestPrintedLevel: 4,
		},
		"Info": {
			logFunction:                func(l Logger) func() Event { return l.Info },
			expectedLowestPrintedLevel: 3,
		},
		"Warn": {
			logFunction:                func(l Logger) func() Event { return l.Warn },
			expectedLowestPrintedLevel: 2,
		},
		"Error": {
			logFunction:                func(l Logger) func() Event { return l.Error },
			expectedLowestPrintedLevel: 1,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			buf := bytes.Buffer{}
			Default().WithOutput(&buf)
			for settedLevel := 0; settedLevel <= 9; settedLevel++ {
				l := Default().WithOutput(io.Discard).WithLevel(Level(settedLevel))
				event := tCase.logFunction(l)()
				if settedLevel >= tCase.expectedLowestPrintedLevel {
					if _, ok := event.(noopEvent); ok {
						t.Fatalf("Missing expected log. Level: %s, Function: %s", Level(settedLevel).String(), name)
					}

					if !event.IsEnabled() {
						t.Fatalf("Unexpected event, wanted to be enabled")
					}
				}
				if settedLevel < tCase.expectedLowestPrintedLevel {
					if _, ok := event.(noopEvent); !ok {
						t.Fatalf("Unexpected log. Level: %d, Function: %s", settedLevel, name)
					}
				}
			}
		})
	}
}

func TestMsg(t *testing.T) {
	t.Run("empty error", func(t *testing.T) {
		l := Default().WithOutput(io.Discard).WithLevel(LevelInfo)
		fields := l.Info().Err(nil).(*defaultEvent).fields
		if want, have := 0, len(fields); want != have {
			t.Fatalf("unexpected number of fields, want %d, have %d", want, have)
		}
	})

	t.Run("empty message", func(t *testing.T) {
		buf := bytes.Buffer{}
		l := Default().WithOutput(&buf).WithLevel(LevelInfo)
		l.Info().Msg("")
		if want, have := 0, buf.Len(); want != have {
			t.Fatalf("unexpected message length, want %d, have %d", want, have)
		}
	})

	t.Run("message", func(t *testing.T) {
		buf := bytes.Buffer{}
		l := Default().WithOutput(&buf).WithLevel(LevelInfo)
		l.Info().
			Bool("a", true).
			Int("b", -1).
			Uint("c", 1).
			Str("d", "x").
			Stringer("e", bytes.NewBufferString("y & z")).
			Bool("f", false).
			Err(errors.New("my error")).
			Msg("my message")

		expected := "[INFO] my message a=true b=-1 c=1 d=\"x\" e=\"y & z\" f=false error=\"my error\"\n"

		// [20:] Skips the timestamp.
		if want, have := expected, buf.String()[20:]; want != have {
			t.Fatalf("unexpected message, want %q, have %q", want, have)
		}
	})
}

func TestLogMessagePrefixes(t *testing.T) {
	buf := bytes.Buffer{}
	l := Default().WithOutput(&buf).WithLevel(LevelTrace)
	testCases := map[string]struct {
		logPrintEvent Event
	}{
		"Trace": {l.Trace()},
		"Debug": {l.Debug()},
		"Info":  {l.Info()},
		"Warn":  {l.Warn()},
		"Error": {l.Error()},
	}
	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			buf.Reset()
			tCase.logPrintEvent.Msg("message")
			if wantToContain, have := strings.ToUpper(name), buf.String(); !strings.Contains(have, wantToContain) {
				t.Errorf("unexpected log entry: want to contain %q, have %q", wantToContain, have)
			}
		})
	}
}

func TestWithLogger(t *testing.T) {
	buf := bytes.Buffer{}
	l := Default().WithOutput(&buf).WithLevel(LevelInfo)
	l2 := l.
		With(
			Bool("a", true),
			Int("b", -1),
			Uint("c", 1),
			Str("d", "x"),
			Stringer("e", bytes.NewBufferString("y & z")),
			Bool("f", false),
		)
	l2.Info().
		Str("g", "w").
		Msg("my message")

	expected := "[INFO] my message a=true b=-1 c=1 d=\"x\" e=\"y & z\" f=false g=\"w\"\n"

	// [20:] Skips the timestamp.
	if want, have := expected, buf.String()[20:]; want != have {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}

	// Check that the original log hasn't been modified.
	buf2 := bytes.Buffer{}
	l = l.WithOutput(&buf2)
	l.Info().
		Str("g", "w").
		Msg("my message")

	expected = "[INFO] my message g=\"w\"\n"

	// [20:] Skips the timestamp.
	if want, have := expected, buf2.String()[20:]; want != have {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}

	// ContextField is an exported func type, so an integrator's field may return
	// nil, a wrapper, a new Event or a disabled one. With must keep what the
	// fields wrote and must not panic; each of these rows panics on the old
	// type assertion.
	returnsNil := func(e Event) Event { e.Str("a", "1"); return nil }
	returnsWrapper := func(e Event) Event { return prefixEvent{e.Str("b", "2")} }
	returnsNew := func(Event) Event { return Default().Info().Str("d", "4") }
	returnsNoop := func(Event) Event { return Noop().Info() }
	customFields := []struct {
		name     string
		fields   []ContextField
		expected string
	}{
		{"nil, then a wrapper", []ContextField{returnsNil, returnsWrapper, Str("c", "3")}, `[INFO] m a="1" b="2" p.c="3"` + "\n"},
		{"a new event, then a wrapper", []ContextField{Str("a", "1"), returnsNew, returnsWrapper}, `[INFO] m d="4" b="2"` + "\n"},
		{"a no-op event", []ContextField{Str("a", "1"), returnsNoop, Str("z", "9")}, `[INFO] m a="1" z="9"` + "\n"},
	}
	for _, tc := range customFields {
		t.Run("custom fields returning "+tc.name, func(t *testing.T) {
			buf := bytes.Buffer{}
			Default().WithOutput(&buf).With(tc.fields...).Info().Msg("m")
			if buf.Len() < 20 {
				t.Fatalf("expected a log line, have %q", buf.String())
			}
			if want, have := tc.expected, buf.String()[20:]; want != have {
				t.Fatalf("unexpected message, want %q, have %q", want, have)
			}
		})
	}
}

func TestWithLoggerAccumulative(t *testing.T) {
	buf := bytes.Buffer{}
	l := Default().WithOutput(&buf).WithLevel(LevelInfo)
	l2 := l.With(Bool("a", true))
	l3 := l2.With(Int("b", -1))
	l3.Info().
		Str("g", "w").
		Msg("my message")

	expected := "[INFO] my message a=true b=-1 g=\"w\"\n"

	// [20:] Skips the timestamp.
	if want, have := expected, buf.String()[20:]; want != have {
		t.Fatalf("unexpected message, want %q, have %q", want, have)
	}
}
