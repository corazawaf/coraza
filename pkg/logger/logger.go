package waf

import(
	"os"
	"log"
	"io"
	"io/ioutil"
	"fmt"
	"time"
	"path"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Logger struct {
	auditlogger *log.Logger
	errorlogger *log.Logger
}


func (l *Logger) Init() error{
	err := l.SetAuditLog("/tmp/audit.log")
	if err != nil{
		return err
	}
	err = l.SetErrorLog("/tmp/error.log")
	if err != nil {
		return err
	}
	return nil
}

func (l *Logger) SetAuditLog(path string) error{
	faudit, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}	
	mw := io.MultiWriter(faudit)
	l.auditlogger = log.New(mw, "", 0)
	return nil
}

func (l *Logger) SetErrorLog(path string) error{
	ferror, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}	
	mw := io.MultiWriter(ferror)
	l.errorlogger = log.New(mw, "", 0)
	return nil
}

func (l *Logger) WriteAudit(tx *Transaction) {
	// 192.168.3.130 192.168.3.1 - - [22/Aug/2009:13:24:20 +0100] "GET / HTTP/1.1" 200 56 "-" "-" SojdH8AAQEAAAugAQAAAAAA "-" /20090822/20090822-1324/20090822-132420-SojdH8AAQEAAAugAQAAAAAA 0 1248
	t := time.Unix(tx.Collections["timestamp"].GetFirstInt64(), 0)
	ts := t.Format("02/Jan/2006:15:04:20 -0700")

	ipsource := tx.Collections["remote_addr"].GetFirstString()
	ipserver := "127.0.0.1"
	requestline := tx.Collections["request_line"].GetFirstString()
	responsecode := tx.Collections["response_status"].GetFirstInt()
	responselength := tx.Collections["response_content_length"].GetFirstInt64()
	requestlength := tx.Collections["request_content_length"].GetFirstInt64()
	p2 := fmt.Sprintf("/%s/%s", t.Format("20060106"), t.Format("20060106-1504"))
	logdir:= path.Join(tx.AuditLogPath1, p2)
	filepath := path.Join(logdir, fmt.Sprintf("/%s-%s", t.Format("20060106-150405"), tx.Id))
	str := fmt.Sprintf("%s %s - - [%s] %q %d %d %q %q %s %q %s %d %d", 
		ipsource, ipserver,	ts,	requestline, responsecode, responselength, "-", "-", tx.Id, "-", filepath, 0, requestlength)	
	err := os.MkdirAll(logdir, 0777) //TODO update with settings mode
	if err != nil{
		fmt.Println("Cannot create directory " + logdir, err)
	}

	jslog := &models.AuditLog{}
	jslog.Parse(&tx.Transaction)
	jsdata := jslog.ToJson()

	err = ioutil.WriteFile(filepath, jsdata, 0600) //TODO update with settings mode
	if err != nil{
		fmt.Println("Error writting logs to " + filepath)
	}
	l.auditlogger.Print(str)
}

func (l *Logger) WriteAccess(tx *Transaction) {
	//127.0.0.1 ABABABABABABABABAB frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
	//https://httpd.apache.org/docs/2.4/logs.html	
}

func (l *Logger) WriteError(error string) {
	//[Fri Sep 09 10:42:29.902022 2011] [core:error] [pid 35708:tid 4328636416] [client 72.15.99.187] File does not exist: /usr/local/apache2/htdocs/favicon.ico
	//https://httpd.apache.org/docs/2.4/logs.html
}

func (l *Logger) Debug(logdata string, v ...interface{}){
	l.WriteError(fmt.Sprintf(logdata, v...))
}

func (l *Logger) Info(logdata string, v ...interface{}){
	l.WriteError(fmt.Sprintf(logdata, v...))
}

func (l *Logger) Warn(logdata string, v ...interface{}){
	l.WriteError(fmt.Sprintf(logdata, v...))
}

func (l *Logger) Error(logdata string, v ...interface{}){
	l.WriteError(fmt.Sprintf(logdata, v...))
}

func (l *Logger) Fatal(logdata string, v ...interface{}){
	l.WriteError(fmt.Sprintf(logdata, v...))
	os.Exit(-1)
}

func (l *Logger) BuildSyslog(tx *Transaction) string{
	return ""
}
