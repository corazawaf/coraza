// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package auditlog

import (
	"github.com/corazawaf/coraza/v3/auditlog"
	"github.com/corazawaf/coraza/v3/plugins"
)

func init() {
	plugins.RegisterAuditLogWriter("concurrent", func() auditlog.Writer {
		return noopWriter{}
	})
	plugins.RegisterAuditLogWriter("serial", func() auditlog.Writer {
		return noopWriter{}
	})

	plugins.RegisterAuditLogFormatter("json", noopFormater)
	plugins.RegisterAuditLogFormatter("jsonlegacy", noopFormater)
	plugins.RegisterAuditLogFormatter("native", nativeFormatter)
}
