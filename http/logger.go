// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import "log"

type Logger func(msg string, args ...interface{})

var (
	NoopLogger = func(msg string, args ...interface{}) {}
	StdLogger  = log.Printf
)
