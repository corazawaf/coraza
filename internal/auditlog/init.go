// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !windows && !plan9

// ,!windows,!plan9

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
	RegisterWriter("syslog", func() plugintypes.AuditLogWriter {
		return NewSyslogWriter()
	})

	RegisterFormatter("json", &jsonFormatter{})
	RegisterFormatter("jsonlegacy", &legacyJSONFormatter{})
	RegisterFormatter("native", &nativeFormatter{})
	RegisterFormatter("ocsf", &ocsfFormatter{})
}
