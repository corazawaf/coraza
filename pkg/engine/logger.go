// Copyright 2020 Juan Pablo Tosso
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

import(
	
)

type Logger struct {
	concurrentlogger *ConcurrentLogger
	httplogger *HttpLogger
	logtype int
	initialized bool
}


func (l *Logger) InitConcurrent(path string, directory string) error{
	l.initialized = false
	l.logtype = AUDIT_LOG_CONCURRENT
	cl := &ConcurrentLogger{}
	l.concurrentlogger = cl
	if err := cl.Init(path, directory); err != nil{
		return err
	}
	l.initialized = true
	return nil
}

func (l *Logger) InitHttps(url string, apikey string) error{
	l.logtype = AUDIT_LOG_HTTPS
	l.httplogger = &HttpLogger{}
	l.httplogger.Init(url)
	l.initialized = true
	return nil
}

func (l *Logger) InitScript(script string) error{
	l.logtype = AUDIT_LOG_SCRIPT
	//NOT SUPPORTED YET
	return nil
}

func (l *Logger) WriteAudit(tx *Transaction) error{
	var err error
	if !l.initialized{
		return nil
	}
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