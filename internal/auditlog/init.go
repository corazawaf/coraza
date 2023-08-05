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
	RegisterWriter("https", func() plugintypes.AuditLogWriter {
		return &httpsWriter{}
	})

	RegisterFormatter("json", func() plugintypes.AuditLogFormatter { return &jsonFormatter{} })
	RegisterFormatter("jsonlegacy", func() plugintypes.AuditLogFormatter { return &legacyJSONFormatter{} })
	RegisterFormatter("native", func() plugintypes.AuditLogFormatter { return &nativeFormatter{} })
}
