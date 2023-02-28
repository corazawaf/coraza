// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

/*
	func TestLoggerLogLevels(t *testing.T) {
		waf := NewWAF()
		testCases := map[string]struct {
			logFunction                func(message string)
			expectedLowestPrintedLevel log.Level
		}{
			"Trace": {
				logFunction:                waf.Logger.Trace().Msg,
				expectedLowestPrintedLevel: log.TraceLevel,
			},
			"Debug": {
				logFunction:                waf.Logger.Debug().Msg,
				expectedLowestPrintedLevel: log.DebugLevel,
			},
			"Info": {
				logFunction:                waf.Logger.Info().Msg,
				expectedLowestPrintedLevel: log.InfoLevel,
			},
			"Warn": {
				logFunction:                waf.Logger.Warn().Msg,
				expectedLowestPrintedLevel: log.WarnLevel,
			},
			"Error": {
				logFunction:                waf.Logger.Error().Msg,
				expectedLowestPrintedLevel: log.ErrorLevel,
			},
		}

		for name, tCase := range testCases {
			t.Run(name, func(t *testing.T) {
				for settedLevel := 0; settedLevel <= 9; settedLevel++ {
					l := &inspectableLogger{}
					waf.Logger.Output(l)
					waf.Logger.Level(settedLevel)
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
*/
/*func TestLoggerLevelDefaultsToInfo(t *testing.T) {
	waf := NewWAF()
	waf.Logger.Level(loggers.LogLevel(10))
	if waf.Logger.(*stdDebugLogger).Level != loggers.LogLevelInfo {
		t.Fatalf("Unexpected log level: %d. It should default to Info (%s)", waf.Logger.(*stdDebugLogger).Level, loggers.LogLevelInfo)
	}
}
*/
