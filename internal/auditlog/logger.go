// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// NewConfig returns a Config with default values.
func NewConfig() plugintypes.AuditLogConfig {
	return plugintypes.AuditLogConfig{
		Target:    "",
		FileMode:  0644,
		Dir:       "",
		DirMode:   0755,
		Formatter: nativeFormatter,
	}
}

var writers = map[string]func() plugintypes.AuditLogWriter{}
var formatters = map[string]plugintypes.AuditLogFormatter{}

// RegisterWriter registers a new logger
// it can be used for plugins
func RegisterWriter(name string, writer func() plugintypes.AuditLogWriter) {
	writers[name] = writer
}

// GetWriter returns a logger by name
// It returns an error if it doesn't exist
func GetWriter(name string) (plugintypes.AuditLogWriter, error) {
	logger := writers[strings.ToLower(name)]
	if logger == nil {
		return nil, fmt.Errorf("invalid logger %q", name)
	}
	return logger(), nil
}

// RegisterFormatter registers a new logger format
// it can be used for plugins
func RegisterFormatter(name string, f func(plugintypes.AuditLog) ([]byte, error)) {
	formatters[name] = f
}

// GetFormatter returns a formatter by name
// It returns an error if it doesn't exist
func GetFormatter(name string) (plugintypes.AuditLogFormatter, error) {
	formatter := formatters[strings.ToLower(name)]
	if formatter == nil {
		return nil, fmt.Errorf("invalid formatter %q", name)
	}
	return formatter, nil
}
