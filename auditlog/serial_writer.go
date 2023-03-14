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
	closer    func() error
	log       log.Logger
	formatter Formatter
}

func (sl *serialWriter) Init(c Config) error {
	fileMode := c.FileMode
	sl.formatter = c.Formatter

	var w io.Writer
	if c.File != "" {
		f, err := os.OpenFile(c.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
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

func (sl *serialWriter) Close() error {
	return sl.closer()
}

var _ Writer = (*serialWriter)(nil)
