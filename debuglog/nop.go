// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglog

import (
	"fmt"
)

type noopEvent struct{}

func (noopEvent) Msg(string)                            {}
func (e noopEvent) Str(string, string) Event            { return e }
func (e noopEvent) Err(error) Event                     { return e }
func (e noopEvent) Bool(string, bool) Event             { return e }
func (e noopEvent) Int(string, int) Event               { return e }
func (e noopEvent) Uint(string, uint) Event             { return e }
func (e noopEvent) Stringer(string, fmt.Stringer) Event { return e }
func (e noopEvent) IsEnabled() bool                     { return false }

// Noop returns a Logger which does no logging.
func Noop() Logger {
	return defaultLogger{
		printer: func(Level, string, string) {},
		factory: defaultPrinterFactory,
		level:   LevelNoLog,
	}
}
