// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Currently only used with TinyGo
//go:build tinygo
// +build tinygo

package auditlog

import "github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"

type noopFormatter struct{}

func (noopFormatter) Format(plugintypes.AuditLog) ([]byte, error) {
	return nil, nil
}
func (noopFormatter) MIME() string {
	return ""
}
