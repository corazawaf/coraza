// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package debuglogger

import "fmt"

type NopEvent struct{}

func (NopEvent) Msg(msg string)                                {}
func (e NopEvent) Str(key, val string) Event                   { return e }
func (e NopEvent) Err(err error) Event                         { return e }
func (e NopEvent) Bool(key string, b bool) Event               { return e }
func (e NopEvent) Int(key string, i int) Event                 { return e }
func (e NopEvent) Uint(key string, i uint) Event               { return e }
func (e NopEvent) Stringer(key string, val fmt.Stringer) Event { return e }

func Nop() Logger {
	return defaultLogger{level: LogLevelNoLog}
}
