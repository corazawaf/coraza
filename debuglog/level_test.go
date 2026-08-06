// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
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
			require.Equal(t, test.want, test.level.String(), "unexpected error string")
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
			require.Equal(t, test.isValid, test.level.Valid(), "unexpected validity")
		})
	}
}
