// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package http

import "log"

type Logger func(msg string, args ...interface{})

var (
	NoopLogger = func(msg string, args ...interface{}) {}
	StdLogger  = log.Printf
)
