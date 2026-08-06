// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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
				l := Default().WithOutput(io.Discard).WithLevel(Level(settedLevel))
				event := tCase.logFunction(l)()
				if settedLevel >= tCase.expectedLowestPrintedLevel {
					_, ok := event.(noopEvent)
					require.False(t, ok, "Missing expected log. Level: %s, Function: %s", Level(settedLevel).String(), name)

					require.True(t, event.IsEnabled(), "Unexpected event, wanted to be enabled")
				}
				if settedLevel < tCase.expectedLowestPrintedLevel {
					_, ok := event.(noopEvent)
					require.True(t, ok, "Unexpected log. Level: %d, Function: %s", settedLevel, name)
				}
			}
		})
	}
}

func TestMsg(t *testing.T) {
	t.Run("empty error", func(t *testing.T) {
		l := Default().WithOutput(io.Discard).WithLevel(LevelInfo)
		fields := l.Info().Err(nil).(*defaultEvent).fields
		require.Empty(t, fields, "unexpected number of fields")
	})

	t.Run("empty message", func(t *testing.T) {
		buf := bytes.Buffer{}
		l := Default().WithOutput(&buf).WithLevel(LevelInfo)
		l.Info().Msg("")
		require.Equal(t, 0, buf.Len(), "unexpected message length")
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
		require.Equal(t, expected, buf.String()[20:], "unexpected message")
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
			wantToContain := strings.ToUpper(name)
			require.Contains(t, buf.String(), wantToContain, "unexpected log entry")
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
	require.Equal(t, expected, buf.String()[20:], "unexpected message")

	// Check that the original log hasn't been modified.
	buf2 := bytes.Buffer{}
	l = l.WithOutput(&buf2)
	l.Info().
		Str("g", "w").
		Msg("my message")

	expected = "[INFO] my message g=\"w\"\n"

	// [20:] Skips the timestamp.
	require.Equal(t, expected, buf2.String()[20:], "unexpected message")
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
	require.Equal(t, expected, buf.String()[20:], "unexpected message")
}
