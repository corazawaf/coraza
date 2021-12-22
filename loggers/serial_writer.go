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
	"io/fs"
	"log"
	"os"

	"github.com/jptosso/coraza-waf/v2/types"
)

// serialWriter is used to store logs in a single file
type serialWriter struct {
	file      *os.File
	log       log.Logger
	formatter LogFormatter
}

func (sl *serialWriter) Init(l types.WafConfig) error {
	fileName := l.Get("auditlog_file", "").(string)
	fileMode := l.Get("auditlog_file_mode", fs.FileMode(0644)).(fs.FileMode)
	sl.formatter = l.Get("auditlog_formatter", nativeFormatter).(LogFormatter)
	var err error
	sl.file, err = os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return err
	}
	sl.log.SetFlags(0)
	sl.log.SetOutput(sl.file)
	return nil
}

func (sl *serialWriter) Write(al *AuditLog) error {
	bts, err := sl.formatter(al)
	if err != nil {
		return err
	}
	sl.log.Println(string(bts))
	return nil
}

func (sl *serialWriter) Close() error {
	sl.file.Close()
	return nil
}

var _ LogWriter = (*serialWriter)(nil)
