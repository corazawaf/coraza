// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type concurrentWriter struct {
	mux         *sync.RWMutex
	log         *log.Logger
	logDir      string
	logDirMode  fs.FileMode
	logFileMode fs.FileMode
	formatter   plugintypes.AuditLogFormatter
	io.Closer
}

func (cl *concurrentWriter) Init(c plugintypes.AuditLogConfig) error {
	if c.Target == "" {
		cl.Closer = NoopCloser
		return nil
	}

	cl.logFileMode = c.FileMode
	cl.logDir = c.Dir
	cl.logDirMode = c.DirMode
	cl.formatter = c.Formatter
	cl.mux = &sync.RWMutex{}

	f, err := os.OpenFile(c.Target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, cl.logFileMode)
	if err != nil {
		return err
	}
	cl.Closer = f

	cl.log = log.New(f, "", 0)
	return nil
}

func (cl concurrentWriter) Write(al plugintypes.AuditLog) error {
	if cl.formatter == nil {
		return nil
	}

	// 192.168.3.130 192.168.3.1 - - [22/Aug/2009:13:24:20 +0100] "GET / HTTP/1.1" 200 56 "-" "-" SojdH8AAQEAAAugAQAAAAAA "-" /20090822/20090822-1324/20090822-132420-SojdH8AAQEAAAugAQAAAAAA 0 1248
	t := time.Unix(0, al.Transaction().UnixTimestamp())

	ymd := t.Format("20060102")
	ymdhm := ymd + t.Format("-1504")
	filename := ymdhm + t.Format("05") + "-" + al.Transaction().ID()

	logdir := path.Join(cl.logDir, ymd, ymdhm)
	if err := os.MkdirAll(logdir, cl.logDirMode); err != nil {
		return err
	}

	formattedAL, err := cl.formatter(al)
	if err != nil {
		return err
	}

	filepath := path.Join(logdir, filename)
	if err = os.WriteFile(filepath, formattedAL, cl.logFileMode); err != nil {
		return err
	}

	cl.mux.Lock()
	defer cl.mux.Unlock()

	cl.log.Printf("%s %s - - [%s]", al.Transaction().ClientIP(), al.Transaction().HostIP(), al.Transaction().Timestamp())
	if al.Transaction().HasRequest() {
		cl.log.Printf(
			` "%s %s %s"`,
			al.Transaction().Request().Method(),
			al.Transaction().Request().URI(),
			al.Transaction().Request().HTTPVersion())
	}
	if al.Transaction().HasResponse() {
		cl.log.Printf(` %d`, al.Transaction().Response().Status())
	}
	cl.log.Printf("%s - %s\n", al.Transaction().ID(), filepath)

	return nil
}

var _ plugintypes.AuditLogWriter = (*concurrentWriter)(nil)
