// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/debug"
	_ "github.com/corazawaf/coraza/v3/internal/auditlog"
)

func TestLoggerLogLevels(t *testing.T) {
	waf := NewWAF()
	testCases := map[string]struct {
		logFunction                func(message string, args ...interface{})
		expectedLowestPrintedLevel int
	}{
		"Trace": {
			logFunction:                waf.Logger.Trace,
			expectedLowestPrintedLevel: 9,
		},
		"Debug": {
			logFunction:                waf.Logger.Debug,
			expectedLowestPrintedLevel: 4,
		},
		"Info": {
			logFunction:                waf.Logger.Info,
			expectedLowestPrintedLevel: 3,
		},
		"Warn": {
			logFunction:                waf.Logger.Warn,
			expectedLowestPrintedLevel: 2,
		},
		"Error": {
			logFunction:                waf.Logger.Error,
			expectedLowestPrintedLevel: 1,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			for settedLevel := 0; settedLevel <= 9; settedLevel++ {
				l := &inspectableLogger{}
				waf.Logger.SetOutput(l)
				waf.Logger.SetLevel(debug.Level(settedLevel))
				tCase.logFunction("this is a log")

				if settedLevel >= tCase.expectedLowestPrintedLevel && len(l.entries) != 1 {
					t.Fatalf("Missing expected log. Level: %d, Function: %s", settedLevel, name)
				}
				if settedLevel < tCase.expectedLowestPrintedLevel && len(l.entries) == 1 {
					t.Fatalf("Unexpected log. Level: %d, Function: %s", settedLevel, name)
				}
			}

		})
	}
}

func TestLoggerLevelDefaultsToInfo(t *testing.T) {
	waf := NewWAF()
	waf.Logger.SetLevel(debug.Level(10))
	if waf.Logger.(*stdDebugLogger).Level != debug.LevelInfo {
		t.Fatalf("Unexpected log level: %d. It should default to Info (%s)", waf.Logger.(*stdDebugLogger).Level, debug.LevelInfo)
	}
}
