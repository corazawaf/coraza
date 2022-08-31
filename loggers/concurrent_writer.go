// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package loggers

import (
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

type concurrentWriter struct {
	mux           *sync.RWMutex
	auditlogger   *log.Logger
	auditDir      string
	auditDirMode  fs.FileMode
	auditFileMode fs.FileMode
	formatter     LogFormatter
}

func (cl *concurrentWriter) Init(c types.Config) error {
	cl.auditFileMode = c.Get("auditlog_file_mode", fs.FileMode(0644)).(fs.FileMode)
	cl.auditDir = c.Get("auditlog_dir", "").(string)
	cl.auditDirMode = c.Get("auditlog_dir_mode", fs.FileMode(0755)).(fs.FileMode)
	cl.formatter = c.Get("auditlog_formatter", nativeFormatter).(LogFormatter)
	cl.mux = &sync.RWMutex{}

	faudit := io.Discard
	if fileName := c.Get("auditlog_file", "").(string); fileName != "" {
		f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, cl.auditFileMode)
		if err != nil {
			return err
		}
		faudit = f
	}
	mw := io.MultiWriter(faudit)
	cl.auditlogger = log.New(mw, "", 0)
	return nil
}

func (cl concurrentWriter) Write(al *AuditLog) error {
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
	return nil
}

var _ LogWriter = (*concurrentWriter)(nil)
