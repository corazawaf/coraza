// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package loggers

import (
	"io/fs"
	"log"
	"os"

	"github.com/corazawaf/coraza/v3/types"
)

// serialWriter is used to store logs in a single file
type serialWriter struct {
	file      *os.File
	log       log.Logger
	formatter LogFormatter
}

func (sl *serialWriter) Init(c types.Config) error {
	fileName := c.Get("auditlog_file", "/dev/null").(string)
	fileMode := c.Get("auditlog_file_mode", fs.FileMode(0644)).(fs.FileMode)
	sl.formatter = c.Get("auditlog_formatter", nativeFormatter).(LogFormatter)
	var err error
	sl.file, err = os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return err
	}
	sl.log.SetFlags(0)
	sl.log.SetOutput(sl.file)
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
	sl.file.Close()
	return nil
}

var _ LogWriter = (*serialWriter)(nil)
