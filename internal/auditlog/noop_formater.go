// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Currently only used with TinyGo
//go:build tinygo
// +build tinygo

package auditlog

import (
	"github.com/corazawaf/coraza/v3/auditlog"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
)

func noopFormater(al *auditlog.AuditLog) ([]byte, error) {
	return nil, nil
}

func init() {
	plugins.RegisterAuditLogFormatter("noop", noopFormater)
}
