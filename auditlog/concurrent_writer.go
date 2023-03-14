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
)

type concurrentWriter struct {
	mux           *sync.RWMutex
	auditlogger   *log.Logger
	auditDir      string
	auditDirMode  fs.FileMode
	auditFileMode fs.FileMode
	formatter     Formatter
	closer        func() error
}

func (cl *concurrentWriter) Init(c Config) error {
	cl.auditFileMode = c.FileMode
	cl.auditDir = c.Dir
	cl.auditDirMode = c.DirMode
	cl.formatter = c.Formatter
	cl.mux = &sync.RWMutex{}

	w := io.Discard
	if c.File != "" {
		f, err := os.OpenFile(c.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, cl.auditFileMode)
		if err != nil {
			return err
		}
		w = f
		cl.closer = f.Close
	} else {
		cl.closer = func() error { return nil }
	}
	cl.auditlogger = log.New(w, "", 0)
	return nil
}

func (cl concurrentWriter) Write(al *Log) error {
	// 192.168.3.130 192.168.3.1 - - [22/Aug/2009:13:24:20 +0100] "GET / HTTP/1.1" 200 56 "-" "-" SojdH8AAQEAAAugAQAAAAAA "-" /20090822/20090822-1324/20090822-132420-SojdH8AAQEAAAugAQAAAAAA 0 1248
	t := time.Unix(0, al.Transaction.UnixTimestamp)

	ymd := t.Format("20060102")
	ymdhm := ymd + t.Format("-1504")
	filename := ymdhm + t.Format("05") + "-" + al.Transaction.ID

	logdir := path.Join(cl.auditDir, ymd, ymdhm)
	if err := os.MkdirAll(logdir, cl.auditDirMode); err != nil {
		return err
	}

	jsdata, err := cl.formatter(al)
	if err != nil {
		return err
	}

	filepath := path.Join(logdir, filename)
	if err = os.WriteFile(filepath, jsdata, cl.auditFileMode); err != nil {
		return err
	}

	cl.mux.Lock()
	defer cl.mux.Unlock()

	cl.auditlogger.Printf("%s %s - - [%s]", al.Transaction.ClientIP, al.Transaction.HostIP, al.Transaction.Timestamp)
	if al.Transaction.Request != nil {
		cl.auditlogger.Printf(` "%s %s %s"`, al.Transaction.Request.Method, al.Transaction.Request.URI, al.Transaction.Request.HTTPVersion)
	}
	if al.Transaction.Response != nil {
		cl.auditlogger.Printf(` %d`, al.Transaction.Response.Status)
	}
	cl.auditlogger.Printf("%s - %s\n", al.Transaction.ID, filepath)

	return nil
}

func (cl *concurrentWriter) Close() error {
	return cl.closer()
}

var _ Writer = (*concurrentWriter)(nil)
