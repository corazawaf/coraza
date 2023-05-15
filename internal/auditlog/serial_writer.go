// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"io"
	"log"
	"os"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/environment"
)

// serialWriter is used to store logs in a single file
type serialWriter struct {
	io.Closer
	log       log.Logger
	formatter plugintypes.AuditLogFormatter
}

func (sl *serialWriter) Init(c plugintypes.AuditLogConfig) error {
	if c.Target == "" {
		sl.Closer = noopCloser{}
		return nil
	}

	var f io.Writer
	switch c.Target {
	case "/dev/stdout":
		f = os.Stdout
		sl.Closer = noopCloser{}
	case "/dev/stderr":
		f = os.Stderr
		sl.Closer = noopCloser{}
	default:
		if !environment.HasAccessToFS {
			sl.Closer = noopCloser{}
			return nil
		}

		ff, err := os.OpenFile(c.Target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, c.FileMode)
		if err != nil {
			return err
		}
		f = ff
		sl.Closer = ff
	}

	sl.formatter = c.Formatter
	sl.log.SetFlags(0)
	sl.log.SetOutput(f)
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
	sl.log.Println(string(bts))
	return nil
}

var _ plugintypes.AuditLogWriter = (*serialWriter)(nil)
