package engine

import(
	"log"
	"sync"
	"os"
	"io"
	"io/ioutil"
	"time"
	"fmt"
	"path"
)

type ConcurrentLogger struct{
	auditlogger *log.Logger
	mux *sync.RWMutex
	file string
	directory string
}

func (l *ConcurrentLogger) Init(file string, directory string) error{
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

func (l *ConcurrentLogger) WriteAudit(tx *Transaction) error{
	l.mux.Lock()
	defer l.mux.Unlock()
	// 192.168.3.130 192.168.3.1 - - [22/Aug/2009:13:24:20 +0100] "GET / HTTP/1.1" 200 56 "-" "-" SojdH8AAQEAAAugAQAAAAAA "-" /20090822/20090822-1324/20090822-132420-SojdH8AAQEAAAugAQAAAAAA 0 1248
	t := time.Unix(0, tx.Collections["timestamp"].GetFirstInt64())
	ts := t.Format("02/Jan/2006:15:04:20 -0700")

	ipsource := tx.Collections["remote_addr"].GetFirstString()
	ipserver := "-"
	requestline := tx.Collections["request_line"].GetFirstString()
	responsecode := tx.Collections["response_status"].GetFirstInt()
	responselength := tx.Collections["response_content_length"].GetFirstInt64()
	requestlength := tx.Collections["request_content_length"].GetFirstInt64()
	// append the two directories
	p2 := fmt.Sprintf("/%s/%s", t.Format("20060102"), t.Format("20060102-1504"))
	logdir:= path.Join(tx.WafInstance.AuditLogStorageDir, p2)
	// Append the filename
	filepath := path.Join(logdir, fmt.Sprintf("/%s-%s", t.Format("20060102-150405"), tx.Id))
	str := fmt.Sprintf("%s %s - - [%s] %q %d %d %q %q %s %q %s %d %d", 
		ipsource, ipserver,	ts,	requestline, responsecode, responselength, "-", "-", tx.Id, "-", filepath, 0, requestlength)	
	err := os.MkdirAll(logdir, 0777) //TODO update with settings mode
	if err != nil{
		return err
	}

	jsdata := tx.ToAuditJson()

	err = ioutil.WriteFile(filepath, jsdata, 0600) //TODO update with settings mode
	if err != nil{
		return err
	}
	l.auditlogger.Print(str)
	return nil
}