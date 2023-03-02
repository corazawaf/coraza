// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglogger

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

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
				l := Default().WithOutput(io.Discard).WithLevel(LogLevel(settedLevel))
				event := tCase.logFunction(l)()
				if settedLevel >= tCase.expectedLowestPrintedLevel {
					if _, ok := event.(NopEvent); ok {
						t.Fatalf("Missing expected log. Level: %s, Function: %s", LogLevel(settedLevel).String(), name)
					}
				}
				if settedLevel < tCase.expectedLowestPrintedLevel {
					if _, ok := event.(NopEvent); !ok {
						t.Fatalf("Unexpected log. Level: %d, Function: %s", settedLevel, name)
					}
				}
			}
		})
	}
}

func TestMsg(t *testing.T) {
	t.Run("empty error", func(t *testing.T) {
		l := Default().WithOutput(io.Discard).WithLevel(LogLevelInfo)
		fields := l.Info().Err(nil).(*defaultEvent).fields
		if want, have := 0, len(fields); want != have {
			t.Fatalf("unexpected number of fields, want %d, have %d", want, have)
		}
	})

	t.Run("empty message", func(t *testing.T) {
		buf := bytes.Buffer{}
		l := Default().WithOutput(&buf).WithLevel(LogLevelInfo)
		l.Info().Msg("")
		if want, have := 0, buf.Len(); want != have {
			t.Fatalf("unexpected message length, want %d, have %d", want, have)
		}
	})

	t.Run("message", func(t *testing.T) {
		buf := bytes.Buffer{}
		l := Default().WithOutput(&buf).WithLevel(LogLevelInfo)
		l.Info().
			Bool("a", true).
			Int("b", -1).
			Uint("c", 1).
			Str("d", "x").
			Stringer("e", bytes.NewBufferString("y & z")).
			Err(errors.New("my error")).
			Msg("my message")

		expected := "[ERROR] my message a=true b=-1 c=1 d=x e=\"y & z\" error=\"my error\"\n"

		// [20:] Skips the timestamp.
		if want, have := expected, buf.String()[20:]; want != have {
			t.Fatalf("unexpected message, want %q, have %q", want, have)
		}
	})

	t.Run("message with Errs", func(t *testing.T) {
		buf := bytes.Buffer{}
		l := Default().WithOutput(&buf).WithLevel(LogLevelInfo)
		l.Info().
			Errs(errors.New("my error a"), errors.New("my error b")).
			Msg("my message")

		expected := "[ERROR] my message errors[0]=\"my error a\" errors[1]=\"my error b\"\n"

		// [20:] Skips the timestamp.
		if want, have := expected, buf.String()[20:]; want != have {
			t.Fatalf("unexpected message, want %q, have %q", want, have)
		}
	})
}