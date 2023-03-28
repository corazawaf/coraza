// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"io"
	"log"
	"os"
)

// serialWriter is used to store logs in a single file
type serialWriter struct {
	io.Closer
	formatter Formatter
	log       log.Logger
}

func (sl *serialWriter) Init(c Config) error {
	if c.File == "" {
		sl.Closer = noopCloser{}
		return nil
	}

	fileMode := c.FileMode
	sl.formatter = c.Formatter

	f, err := os.OpenFile(c.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return err
	}
	sl.Closer = f

	sl.log.SetFlags(0)
	sl.log.SetOutput(f)
	return nil
}

func (sl *serialWriter) Write(al *Log) error {
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

var _ Writer = (*serialWriter)(nil)
