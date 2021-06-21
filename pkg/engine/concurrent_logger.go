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

package engine

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

type ConcurrentLogger struct {
	auditlogger *log.Logger
	mux         *sync.RWMutex
	file        string
	directory   string
}

func (l *ConcurrentLogger) Init(file string, directory string) error {
	l.mux = &sync.RWMutex{}
	faudit, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	mw := io.MultiWriter(faudit)
	l.auditlogger = log.New(mw, "", 0)
	l.file = file
	l.directory = directory
	return nil
}

func (l *ConcurrentLogger) WriteAudit(tx *Transaction) error {
	l.mux.Lock()
	defer l.mux.Unlock()
	// 192.168.3.130 192.168.3.1 - - [22/Aug/2009:13:24:20 +0100] "GET / HTTP/1.1" 200 56 "-" "-" SojdH8AAQEAAAugAQAAAAAA "-" /20090822/20090822-1324/20090822-132420-SojdH8AAQEAAAugAQAAAAAA 0 1248
	t := time.Unix(0, tx.Timestamp)
	ts := t.Format("02/Jan/2006:15:04:20 -0700")

	ipsource := tx.GetCollection(VARIABLE_REMOTE_ADDR).GetFirstString("")
	ipserver := "-"
	requestline := tx.GetCollection(VARIABLE_REQUEST_LINE).GetFirstString("")
	responsecode := tx.GetCollection(VARIABLE_RESPONSE_STATUS).GetFirstInt("")
	responselength := tx.GetCollection(VARIABLE_RESPONSE_CONTENT_LENGTH).GetFirstInt64("")
	requestlength := 0 //TODO
	// append the two directories
	// Append the filename
	logdir, fname := l.GetAuditPath(tx)
	filepath := path.Join(logdir, fname)
	str := fmt.Sprintf("%s %s - - [%s] %q %d %d %q %q %s %q %s %d %d",
		ipsource, ipserver, ts, requestline, responsecode, responselength, "-", "-", tx.Id, "-", filepath, 0, requestlength)
	err := os.MkdirAll(logdir, 0777) //TODO update with settings mode
	if err != nil {
		return err
	}

	jsdata := tx.ToAuditJson()

	err = ioutil.WriteFile(filepath, jsdata, 0600) //TODO update with settings mode
	if err != nil {
		return err
	}
	l.auditlogger.Print(str)
	return nil
}

func (l *ConcurrentLogger) GetAuditPath(tx *Transaction) (string, string) {
	t := time.Unix(0, tx.Timestamp)

	// append the two directories
	p2 := fmt.Sprintf("/%s/%s/", t.Format("20060102"), t.Format("20060102-1504"))
	logdir := path.Join(tx.Waf.AuditLogStorageDir, p2)
	// Append the filename
	filename := fmt.Sprintf("/%s-%s", t.Format("20060102-150405"), tx.Id)
	return logdir, filename
}
