// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package auditlog

func init() {
	RegisterWriter("concurrent", func() Writer {
		return noopWriter{}
	})
	RegisterWriter("serial", func() Writer {
		return noopWriter{}
	})

	RegisterFormatter("json", noopFormater)
	RegisterFormatter("jsonlegacy", noopFormater)
	RegisterFormatter("native", nativeFormatter)
}
