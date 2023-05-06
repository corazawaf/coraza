// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

func init() {
	RegisterWriter("concurrent", func() Writer {
		return &concurrentWriter{}
	})
	RegisterWriter("serial", func() Writer {
		return &serialWriter{}
	})

	RegisterFormatter("json", jsonFormatter)
	RegisterFormatter("jsonlegacy", legacyJSONFormatter)
	RegisterFormatter("native", nativeFormatter)
}
