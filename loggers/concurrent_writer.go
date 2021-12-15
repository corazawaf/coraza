// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loggers

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"sync"
	"time"
)

type concurrentWriter struct {
	mux         *sync.RWMutex
	auditlogger *log.Logger
	options     LoggerOptions
}

func (cl *concurrentWriter) Init(l LoggerOptions) error {
	cl.mux = &sync.RWMutex{}
	faudit, err := os.OpenFile(l.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, l.FileMode)
	if err != nil {
		return err
	}
	mw := io.MultiWriter(faudit)
	cl.options = l
	cl.auditlogger = log.New(mw, "", 0)
	return nil
}

func (cl concurrentWriter) Write(al AuditLog) error {
	// 192.168.3.130 192.168.3.1 - - [22/Aug/2009:13:24:20 +0100] "GET / HTTP/1.1" 200 56 "-" "-" SojdH8AAQEAAAugAQAAAAAA "-" /20090822/20090822-1324/20090822-132420-SojdH8AAQEAAAugAQAAAAAA 0 1248
	t := time.Unix(0, al.Transaction.UnixTimestamp)

	// append the two directories
	p2 := fmt.Sprintf("/%s/%s/", t.Format("20060102"), t.Format("20060102-1504"))
	logdir := path.Join(cl.options.Dir, p2)
	// Append the filename
	fname := fmt.Sprintf("/%s-%s", t.Format("20060102-150405"), al.Transaction.ID)
	filepath := path.Join(logdir, fname)
	str := fmt.Sprintf("%s %s - - [%s] %q %d %d %q %q %s %q %s %d %d",
		al.Transaction.ClientIP, al.Transaction.HostIP, al.Transaction.Timestamp,
		fmt.Sprintf("%s %s %s", al.Transaction.Request.Method, al.Transaction.Request.URI,
			al.Transaction.Request.HTTPVersion),
		al.Transaction.Response.Status, 0 /*response length*/, "-", "-", al.Transaction.ID,
		"-", filepath, 0, 0 /*request length*/)
	err := os.MkdirAll(logdir, cl.options.DirMode)
	if err != nil {
		return err
	}

	jsdata, err := cl.options.Formatter(al)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath, []byte(jsdata), cl.options.FileMode)
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
