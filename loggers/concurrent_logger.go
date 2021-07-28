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
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type ConcurrentLogger struct {
	auditlogger *log.Logger
	mux         *sync.RWMutex
	file        string
	directory   string
	dirMode     fs.FileMode
	fileMode    fs.FileMode
}

func (l *ConcurrentLogger) New(args []string) error {
	var err error
	if len(args) > 1 {
		l.file = args[0]
		l.directory = args[1]
		// fs.FileModes are octal (base 8)
		dm, err := strconv.ParseInt(args[2], 8, 32)
		if err != nil {
			return err
		}
		l.dirMode = fs.FileMode(dm)
		fm, err := strconv.ParseInt(args[3], 8, 32)
		if err != nil {
			return err
		}
		l.fileMode = fs.FileMode(fm)
	}
	l.mux = &sync.RWMutex{}
	faudit, err := os.OpenFile(l.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	mw := io.MultiWriter(faudit)
	l.auditlogger = log.New(mw, "", 0)
	return nil
}

func (l *ConcurrentLogger) Write(al *AuditLog) {
	// 192.168.3.130 192.168.3.1 - - [22/Aug/2009:13:24:20 +0100] "GET / HTTP/1.1" 200 56 "-" "-" SojdH8AAQEAAAugAQAAAAAA "-" /20090822/20090822-1324/20090822-132420-SojdH8AAQEAAAugAQAAAAAA 0 1248
	t := time.Unix(0, al.Transaction.UnixTimestamp)

	// append the two directories
	p2 := fmt.Sprintf("/%s/%s/", t.Format("20060102"), t.Format("20060102-1504"))
	logdir := path.Join(l.directory, p2)
	// Append the filename
	fname := fmt.Sprintf("/%s-%s", t.Format("20060102-150405"), al.Transaction.Id)
	filepath := path.Join(logdir, fname)
	str := fmt.Sprintf("%s %s - - [%s] %q %d %d %q %q %s %q %s %d %d",
		al.Transaction.ClientIp, al.Transaction.HostIp, al.Transaction.Timestamp,
		fmt.Sprintf("%s %s %s", al.Transaction.Request.Method, al.Transaction.Request.Uri,
			al.Transaction.Request.HttpVersion),
		al.Transaction.Response.Status, 0 /*response length*/, "-", "-", al.Transaction.Id,
		"-", filepath, 0, 0 /*request length*/)
	err := os.MkdirAll(logdir, l.dirMode)
	if err != nil {
		logrus.Error("Failed to create concurrent audit path")
		return
	}

	jsdata, err := al.JSON()
	if err != nil {
		return
	}
	err = ioutil.WriteFile(filepath, jsdata, l.fileMode)
	if err != nil {
		return
	}
	l.mux.Lock()
	defer l.mux.Unlock()
	l.auditlogger.Println(str)
}

func (cl *ConcurrentLogger) Close() {
}
