package waf

import(
	"os"
	"log"
	"io"
	"fmt"
	"time"
	"strings"
)

type Logger struct {
	auditlogger *log.Logger
	accesslogger *log.Logger
	errorlogger *log.Logger
}


func (l *Logger) Init() error{
	faudit, err := os.OpenFile("/tmp/audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}	
	mw := io.MultiWriter(faudit)
	l.auditlogger = log.New(mw, "", 0)

	faccess, err := os.OpenFile("/tmp/access.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}	
	mw = io.MultiWriter(faccess)
	l.accesslogger = log.New(mw, "", 0)


	ferror, err := os.OpenFile("/tmp/error.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}	
	mw = io.MultiWriter(ferror)
	l.errorlogger = log.New(mw, "", 0)
	return nil
}

func (l *Logger) WriteAudit(tx *Transaction) {
	// [Fri Sep 09 10:42:29.902022 2011] block "GET /apache_pb.gif HTTP/1.0" ABABABABABABABABAB [112 1224] ["audit message 1" "audit message 2"]
	t := time.Unix(tx.Collections["timestamp"].GetFirstInt64(), 0)
	ts := t.Format("Mon Jan 02 15:04:05 2006")
	//OPTIMIZAR:
	ids := []string{}
	for _, rule := range tx.MatchedRules {
		r := fmt.Sprintf("[id \"%d\"]", rule.Id)
		ids = append(ids, r)
	}
	idlist := strings.Join(ids, " ")
	str := fmt.Sprintf("[%s] block \"GET /apache_pb.gif\" ABABABABABABABABAB [%s] [\"audit message 1\" \"audit message 2\"]", ts, idlist)

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