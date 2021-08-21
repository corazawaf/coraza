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

// ModsecLogger is used to store logs compatible with go-FTW
type ModsecLogger struct {
	file *os.File
	log  log.Logger
}

func (sl *ModsecLogger) New(args []string) error {
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

func (sl *ModsecLogger) Write(al *AuditLog) error {
	timestamp := al.Transaction.Timestamp
	address := al.Transaction.ClientIp
	rules := ""
	phase := 5
	msgs := ""
	severity := ""
	uri := ""
	status := 0
	if al.Transaction.Request != nil {
		uri = al.Transaction.Request.Uri
	}
	if al.Transaction.Response != nil {
		status = al.Transaction.Response.Status
	}
	logdata := ""

	id := al.Transaction.Id
	err := fmt.Sprintf("Access denied with code %d (phase %d)", status, phase)
	for _, r := range al.Messages {
		rules += fmt.Sprintf("[id \"%d\"] ", r.Data.Id)
		msgs += fmt.Sprintf("[msg \"%s\"]", r.Data.Msg)
	}
	data := fmt.Sprintf("[%s] [error] [client %s] Coraza: %s. %s %s %s [severity \"%s\"] [uri \"%s\"] [unique_id \"%s\"]",
		timestamp, address, err, logdata, rules, msgs, severity, uri, id)
	sl.log.Println(data)
	return nil
}

func (sl *ModsecLogger) Close() error {
	sl.file.Close()
	return nil
}
