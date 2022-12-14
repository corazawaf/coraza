// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package loggers

import (
	"io"
	"io/fs"
	"log"
	"os"

	"github.com/corazawaf/coraza/v3/types"
)

// serialWriter is used to store logs in a single file
type serialWriter struct {
	closer    func() error
	log       log.Logger
	formatter LogFormatter
}

func (sl *serialWriter) Init(c types.Config) error {
	fileMode := c.Get("auditlog_file_mode", fs.FileMode(0644)).(fs.FileMode)
	sl.formatter = c.Get("auditlog_formatter", nativeFormatter).(LogFormatter)

	fileName := c.Get("auditlog_file", "").(string)
	var w io.Writer
	if fileName != "" {
		f, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
		if err != nil {
			return err
		}
		w = f
		sl.closer = f.Close
	} else {
		w = io.Discard
		sl.closer = func() error { return nil }
	}
	sl.log.SetFlags(0)
	sl.log.SetOutput(w)
	return nil
}

func (sl *serialWriter) Write(al *AuditLog) error {
	bts, err := sl.formatter(al)
	if err != nil {
		return err
	}
	sl.log.Println(string(bts))
	return nil
}

func (sl *serialWriter) Close() error {
	return sl.closer()
}

var _ LogWriter = (*serialWriter)(nil)
