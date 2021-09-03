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
	"errors"
	"log/syslog"
)

type SyslogLogger struct {
	format formatter
	writer *syslog.Writer
}

func (sl *SyslogLogger) New(args map[string]string) error {
	var err error
	if len(args) != 2 {
		return errors.New("invalid arguments count for syslog logger")
	}
	server := args["server"]
	format := args["format"]
	protocol := args["protocol"]
	if protocol == "" {
		protocol = "tcp"
	}
	if format == "" {
		format = "cef"
	}
	switch format {
	case "cef":
		sl.format = cefFormatter
	default:
		return errors.New("invalid syslog formatter")
	}
	if server == "" {
		server = "127.0.0.1:514"
	}
	sl.writer, err = syslog.Dial(protocol, server, syslog.LOG_ALERT, "com.coraza.waf")
	if err != nil {
		return err
	}
	return nil
}

func (sl *SyslogLogger) Write(al *AuditLog) error {
	l, _ := sl.format(al)
	return sl.writer.Alert(l) //returns error but whatever
}

func (sl *SyslogLogger) Close() error {
	return sl.writer.Close()
}

var _ Logger = (*SyslogLogger)(nil)
