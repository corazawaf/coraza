// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/loggers"
)

func TestLoggerLogLevels(t *testing.T) {
	waf := NewWAF()
	testCases := map[string]struct {
		logFunction                 func(message string, args ...interface{})
		expectedLowestPrintedLevels int
	}{
		"Trace": {
			logFunction:                 waf.Logger.Trace,
			expectedLowestPrintedLevels: 6,
		},
		"Debug": {
			logFunction:                 waf.Logger.Debug,
			expectedLowestPrintedLevels: 4,
		},
		"Info": {
			logFunction:                 waf.Logger.Info,
			expectedLowestPrintedLevels: 3,
		},
		"Warn": {
			logFunction:                 waf.Logger.Warn,
			expectedLowestPrintedLevels: 2,
		},
		"Error": {
			logFunction:                 waf.Logger.Error,
			expectedLowestPrintedLevels: 1,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			for settedLevel := 0; settedLevel <= 9; settedLevel++ {
				l := &inspectableLogger{}
				waf.Logger.SetOutput(l)
				waf.Logger.SetLevel(loggers.LogLevel(settedLevel))
				tCase.logFunction("this is a log")

				if settedLevel >= tCase.expectedLowestPrintedLevels && len(l.entries) != 1 {
					t.Fatalf("Missing expected log. Level: %d, Function: %s", settedLevel, name)
				}
				if settedLevel < tCase.expectedLowestPrintedLevels && len(l.entries) == 1 {
					t.Fatalf("Unexpected log. Level: %d, Function: %s", settedLevel, name)
				}
			}

		})
	}
}

func TestLoggerLevelDefaultsToInfo(t *testing.T) {
	waf := NewWAF()
	waf.Logger.SetLevel(loggers.LogLevel(10))
	if waf.Logger.(*stdDebugLogger).Level != loggers.LogLevelInfo {
		t.Fatalf("Unexpected log level: %d. It should default to Info (%s)", waf.Logger.(*stdDebugLogger).Level, loggers.LogLevelInfo)
	}
}
