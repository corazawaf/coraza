// Copyright 2022 the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build (windows || plan9) && !tinygo
// +build windows plan9
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
	RegisterWriter("syslog", func() plugintypes.AuditLogWriter {
		return &noopWriter{}
	})

	RegisterFormatter("json", &jsonFormatter{})
	RegisterFormatter("jsonlegacy", &legacyJSONFormatter{})
	RegisterFormatter("native", &nativeFormatter{})
	RegisterFormatter("ocsf", &ocsfFormatter{})
}
