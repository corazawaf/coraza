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
	"bufio"
	"fmt"
	"os"
)

// ApacheLogger is used to store logs compatible with go-FTW
type ApacheLogger struct {
	file   *os.File
	writer *io.Writter
}

func (sl *ApacheLogger) New(file string, dir string, filemode int, dirmode int) {
	var err error
	sl.file, err = os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	sl.writter = bufio.NewWriter(sl.file)
}

func (sl *ApacheLogger) Write(log AuditLog) {
	opts := []string{
		"ddd MMM DD HH:mm:ss.S YYYY", // Timestamp
		"ip address",
		"error",
		"operator",
		"params",
		"variable",
		"rules",
		"",
	}
	variable := ""
	clientIp := ""
	status := 0
	phase := 0
	id := ""
	url := ""
	severity := ""
	ts := "ddd MMM DD HH:mm:ss.S YYYY"
	for _, r := range log.Rules {
		opts["rules"] += fmt.Sprintf("[id \"%d\"] ", r.Id)
	}
	data := fmt.Sprintf("[%s] [error] [client %s] ModSecurity: Access denied with code 505 (phase 1). Match of \"rx ^HTTP/(0.9|1.[01])$\" against \"REQUEST_PROTOCOL\" required. %s %s [severity \"%s\"] [uri \"%s\"] [unique_id \"%s\"]\n", opts)
	sl.writter.WriteString(data)
}

func (sl *ApacheLogger) Close() {
	sl.file.Close()
	sl.writter.Flush()
}
