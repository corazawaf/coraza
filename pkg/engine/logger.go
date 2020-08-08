package engine

import(
)

type Logger struct {
	concurrentlogger *ConcurrentLogger
	httplogger *HttpLogger
	logtype int
}


func (l *Logger) InitConcurrent(path string, directory string) error{
	l.logtype = AUDIT_LOG_CONCURRENT
	return nil
}

func (l *Logger) InitHttps(url string, apikey string) error{
	l.logtype = AUDIT_LOG_HTTPS
	l.httplogger = &HttpLogger{}
	l.httplogger.Init(url)

	return nil
}

func (l *Logger) InitScript(script string) error{
	l.logtype = AUDIT_LOG_SCRIPT
	//NOT SUPPORTED YET
	return nil
}

func (l *Logger) WriteAudit(tx *Transaction) error{
	var err error
	switch l.logtype{
	case AUDIT_LOG_CONCURRENT:
		err = l.concurrentlogger.WriteAudit(tx)
		break
	case AUDIT_LOG_HTTPS:
		err = l.httplogger.Add(tx)
		break
	}

	return err
}