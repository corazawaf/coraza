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
	"log"
	"os"
)

// serialWriter is used to store logs in a single file
type serialWriter struct {
	file    *os.File
	log     log.Logger
	options LoggerOptions
}

func (sl *serialWriter) Init(l LoggerOptions) error {
	sl.options = l
	var err error
	sl.file, err = os.OpenFile(sl.options.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, sl.options.FileMode)
	if err != nil {
		return err
	}
	sl.log.SetFlags(0)
	sl.log.SetOutput(sl.file)
	if sl.options.Formatter == nil {
		return fmt.Errorf("formetter cannot be nil")
	}
	return nil
}

func (sl *serialWriter) Write(al AuditLog) error {
	data, err := sl.options.Formatter(al)
	if err != nil {
		return err
	}

	sl.log.Println(string(data))
	return nil
}

func (sl *serialWriter) Close() error {
	sl.file.Close()
	return nil
}

var _ LogWriter = (*serialWriter)(nil)
