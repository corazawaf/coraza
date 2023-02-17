// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Currently only used with TinyGo
//go:build tinygo
// +build tinygo

package auditlog

import (
	"github.com/corazawaf/coraza/v3/plugins"
	"github.com/corazawaf/coraza/v3/types"
)

// noopWriter is used to store logs in a single file
type noopWriter struct{}

func (noopWriter) Init(types.Config) error        { return nil }
func (noopWriter) Write(*auditlog.AuditLog) error { return nil }
func (noopWriter) Close() error                   { return nil }

var _ LogWriter = (*noopWriter)(nil)

func init() {
	plugins.RegisterAuditLogWriter("noop", func() LogWriter { return &noopWriter{} })
}
