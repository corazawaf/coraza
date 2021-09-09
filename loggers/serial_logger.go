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
	"log"
	"os"
)

// SerialLogger is used to store logs compatible with go-FTW
type SerialLogger struct {
	file   *os.File
	log    log.Logger
	format formatter
}

func (sl *SerialLogger) New(args map[string]string) error {
	var err error
	if len(args) == 0 {
		return errors.New("syntax error: apache /path/to/file.log [filemode]")
	}
	file := args["file"]
	if file == "" {
		return errors.New("file cannot be empty")
	}
	format := args["format"]
	if format == "" {
		format = "modsec"
	}
	fn, err := getFormatter(format)
	if err != nil {
		return err
	}
	sl.format = fn
	sl.file, err = os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	sl.log.SetFlags(0)
	sl.log.SetOutput(sl.file)
	return nil
}

func (sl *SerialLogger) Write(al *AuditLog) error {
	data, err := sl.format(al)
	if err != nil {
		return err
	}

	sl.log.Println(data)
	return nil
}

func (sl *SerialLogger) Close() error {
	sl.file.Close()
	return nil
}

var _ Logger = (*SerialLogger)(nil)
