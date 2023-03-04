// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglogger

import (
	"fmt"
	"testing"
)

func TestLevelString(t *testing.T) {
	var tests = []struct {
		level LogLevel
		want  string
	}{
		{LogLevelNoLog, "NOLOG"},
		{LogLevelError, "ERROR"},
		{LogLevelWarn, "WARN"},
		{LogLevelInfo, "INFO"},
		{LogLevelDebug, "DEBUG"},
		{LogLevelTrace, "TRACE"},
		{LogLevelUnknown, "UNKNOWN"},
		{LogLevel(11), "UNKNOWN"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("level %d", test.level), func(t *testing.T) {
			if want, have := test.want, test.level.String(); want != have {
				t.Errorf("unexpected error string, want %q, have %q", want, have)
			}
		})
	}
}

func TestLevelValid(t *testing.T) {
	var tests = []struct {
		level   LogLevel
		isValid bool
	}{
		{LogLevelUnknown, false},
		{LogLevelNoLog, true},
		{LogLevelError, true},
		{LogLevelWarn, true},
		{LogLevelInfo, true},
		{LogLevelDebug, true},
		{LogLevelTrace, true},
		{LogLevel(11), false},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("level %d", test.level), func(t *testing.T) {
			if want, have := test.isValid, test.level.Valid(); want != have {
				t.Errorf("unexpected validity, want %t, have %t", want, have)
			}
		})
	}
}
