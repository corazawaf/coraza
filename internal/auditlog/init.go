// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"

func init() {
	RegisterWriter("concurrent", func() plugintypes.AuditLogWriter {
		return &concurrentWriter{}
	})
	RegisterWriter("serial", func() plugintypes.AuditLogWriter {
		return &serialWriter{}
	})

	RegisterFormatter("json", jsonFormatter)
	RegisterFormatter("jsonlegacy", legacyJSONFormatter)
	RegisterFormatter("native", nativeFormatter)
}
