// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"io"
	"log"
	"os"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// serialWriter is used to store logs in a single file
type serialWriter struct {
	io.Closer
	logger    log.Logger
	formatter plugintypes.AuditLogFormatter
}

func (sl *serialWriter) Init(c plugintypes.AuditLogConfig) error {
	sl.Closer = NoopCloser
	if c.Target == "" {
		return nil
	}

	var f io.Writer
	switch c.Target {
	case "/dev/stdout":
		f = os.Stdout
	case "/dev/stderr":
		f = os.Stderr
	default:
		ff, err := os.OpenFile(c.Target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, c.FileMode)
		if err != nil {
			return err
		}
		f = ff
		sl.Closer = ff
	}

	sl.formatter = c.Formatter
	sl.logger.SetFlags(0)
	sl.logger.SetOutput(f)
	return nil
}

func (sl *serialWriter) Write(al plugintypes.AuditLog) error {
	if sl.formatter == nil {
		return nil
	}

	bts, err := sl.formatter(al)
	if err != nil {
		return err
	}
	sl.logger.Println(string(bts))
	return nil
}

var _ plugintypes.AuditLogWriter = (*serialWriter)(nil)
