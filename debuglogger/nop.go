// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglogger

import "fmt"

type NopEvent struct{}

func (NopEvent) Msg(string)                            {}
func (e NopEvent) Str(string, string) Event            { return e }
func (e NopEvent) Err(error) Event                     { return e }
func (e NopEvent) Bool(string, bool) Event             { return e }
func (e NopEvent) Int(string, int) Event               { return e }
func (e NopEvent) Uint(string, uint) Event             { return e }
func (e NopEvent) Stringer(string, fmt.Stringer) Event { return e }

func Nop() Logger {
	return defaultLogger{level: LogLevelNoLog}
}
