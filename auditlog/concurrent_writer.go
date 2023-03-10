// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"fmt"
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
	formatter     LogFormatter
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

	// append the two directories
	p2 := fmt.Sprintf("/%s/%s/", t.Format("20060102"), t.Format("20060102-1504"))
	logdir := path.Join(cl.auditDir, p2)
	// Append the filename
	fname := fmt.Sprintf("/%s-%s", t.Format("20060102-150405"), al.Transaction.ID)
	filepath := path.Join(logdir, fname)
	str := fmt.Sprintf("%s %s - - [%s] %q %d %d %q %q %s %q %s %d %d",
		al.Transaction.ClientIP, al.Transaction.HostIP, al.Transaction.Timestamp,
		fmt.Sprintf("%s %s %s", al.Transaction.Request.Method, al.Transaction.Request.URI,
			al.Transaction.Request.HTTPVersion),
		al.Transaction.Response.Status, 0 /*response length*/, "-", "-", al.Transaction.ID,
		"-", filepath, 0, 0 /*request length*/)
	err := os.MkdirAll(logdir, cl.auditDirMode)
	if err != nil {
		return err
	}

	jsdata, err := cl.formatter(al)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath, []byte(jsdata), cl.auditFileMode)
	if err != nil {
		return err
	}
	cl.mux.Lock()
	defer cl.mux.Unlock()
	cl.auditlogger.Println(str)
	return nil
}

func (cl *concurrentWriter) Close() error {
	return cl.closer()
}

var _ LogWriter = (*concurrentWriter)(nil)
