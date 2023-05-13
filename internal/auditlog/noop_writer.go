// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Currently only used with TinyGo
//go:build tinygo
// +build tinygo

package auditlog

import "github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"

// noopWriter is used to store logs in a single file
type noopWriter struct{}

func (noopWriter) Init(plugintypes.AuditLogConfig) error { return nil }
func (noopWriter) Write(plugintypes.AuditLog) error      { return nil }
func (noopWriter) Close() error                          { return nil }

var _ plugintypes.AuditLogWriter = (*noopWriter)(nil)
