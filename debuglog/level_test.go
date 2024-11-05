// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

import (
	"fmt"
	"testing"
)

func TestLevelString(t *testing.T) {
	var tests = []struct {
		level Level
		want  string
	}{
		{LevelNoLog, "NOLOG"},
		{LevelError, "ERROR"},
		{LevelWarn, "WARN"},
		{LevelInfo, "INFO"},
		{LevelDebug, "DEBUG"},
		{LevelTrace, "TRACE"},
		{LevelUnknown, "UNKNOWN"},
		{Level(11), "UNKNOWN"},
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
		level   Level
		isValid bool
	}{
		{LevelUnknown, false},
		{LevelNoLog, true},
		{LevelError, true},
		{LevelWarn, true},
		{LevelInfo, true},
		{LevelDebug, true},
		{LevelTrace, true},
		{Level(11), false},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("level %d", test.level), func(t *testing.T) {
			if want, have := test.isValid, test.level.Valid(); want != have {
				t.Errorf("unexpected validity, want %t, have %t", want, have)
			}
		})
	}
}
