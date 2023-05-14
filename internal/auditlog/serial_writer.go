// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

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
	log       log.Logger
	formatter plugintypes.AuditLogFormatter
}

func (sl *serialWriter) Init(c plugintypes.AuditLogConfig) error {
	if c.File == "" {
		sl.Closer = noopCloser{}
		return nil
	}

	sl.formatter = c.Formatter

	var f *os.File
	switch c.File {
	case "/dev/stdout":
		f = os.Stdout
		sl.Closer = noopCloser{}
	case "/dev/stderr":
		f = os.Stderr
		sl.Closer = noopCloser{}
	default:
		var err error
		if f, err = os.OpenFile(c.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, c.FileMode); err != nil {
			return err
		}
		sl.Closer = f
	}

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
