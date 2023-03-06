// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package auditlog

func init() {
	RegisterLogWriter("concurrent", func() LogWriter {
		return noopWriter{}
	})
	RegisterLogWriter("serial", func() LogWriter {
		return noopWriter{}
	})

	RegisterLogFormatter("json", noopFormater)
	RegisterLogFormatter("jsonlegacy", noopFormater)
	RegisterLogFormatter("native", nativeFormatter)
}
