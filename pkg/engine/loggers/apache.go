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
	"fmt"
	"log"
	"os"
)

// ApacheLogger is used to store logs compatible with go-FTW
type ApacheLogger struct {
	file *os.File
	log  log.Logger
}

func (sl *ApacheLogger) New(args []string) error {
	var err error
	if len(args) == 0 {
		return errors.New("syntax error: apache /path/to/file.log [filemode]")
	}
	sl.file, err = os.OpenFile(args[0], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	sl.log.SetFlags(0)
	sl.log.SetOutput(sl.file)
	return nil
}

func (sl *ApacheLogger) Write(al *AuditLog) {
	timestamp := al.Transaction.Timestamp
	address := ""
	operator := ""
	params := ""
	rules := ""
	phase := 5
	variable := ""
	msgs := ""
	severity := ""
	uri := ""
	id := al.Transaction.Id
	err := fmt.Sprintf("Access denied with code 505 (phase %d)", phase)
	for _, r := range al.Messages {
		rules += fmt.Sprintf("[id \"%d\"] ", r.Data.Id)
	}
	data := fmt.Sprintf("[%s] [error] [client %s] Coraza: %s. Match of \"%s %s\" against \"%s\" required. %s %s [severity \"%s\"] [uri \"%s\"] [unique_id \"%s\"]",
		timestamp, address, err, operator, params, variable, rules, msgs, severity, uri, id)
	sl.log.Println(data)
}

func (sl *ApacheLogger) Close() {
	sl.file.Close()
}
