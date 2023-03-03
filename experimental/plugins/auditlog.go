// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package plugins

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/auditlog"
)

var writers = map[string]func() auditlog.Writer{}
var formatters = map[string]func(al *auditlog.AuditLog) ([]byte, error){}

// RegisterAuditLogWriter registers a new logger
// it can be used for plugins
func RegisterAuditLogWriter(name string, writer func() auditlog.Writer) {
	writers[name] = writer
}

// GetAuditLogWriter returns a logger by name
// It returns an error if it doesn't exist
func GetAuditLogWriter(name string) (auditlog.Writer, error) {
	logger := writers[strings.ToLower(name)]
	if logger == nil {
		return nil, fmt.Errorf("invalid logger %q", name)
	}
	return logger(), nil
}

// RegisterAuditLogFormatter registers a new logger format
// it can be used for plugins
func RegisterAuditLogFormatter(name string, f func(al *auditlog.AuditLog) ([]byte, error)) {
	formatters[name] = f
}

// GetAuditLogFormatter returns a formatter by name
// It returns an error if it doesn't exist
func GetAuditLogFormatter(name string) (auditlog.Formatter, error) {
	formatter := formatters[strings.ToLower(name)]
	if formatter == nil {
		return nil, fmt.Errorf("invalid formatter %q", name)
	}
	return formatter, nil
}
