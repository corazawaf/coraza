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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"
)

func TestCLogFileCreation(t *testing.T) {
	file, err := ioutil.TempFile("/tmp", "tmpaudir")
	if err != nil {
		t.Error("failed to create concurrent logger file")
	}
	l, err := NewAuditLogger()
	if err != nil {
		t.Error("failed to create audit logger", err)
	}
	l.file = file.Name()
	l.directory = "/tmp"
	l.fileMode = 0777
	l.dirMode = 0777
	l.formatter = jsonFormatter
	if err := l.SetWriter("concurrent"); err != nil {
		t.Error(err)
	}
	ts := time.Now().UnixNano()
	al := AuditLog{
		Transaction: AuditTransaction{
			UnixTimestamp: ts,
			ID:            "123",
			Request:       AuditTransactionRequest{},
			Response:      AuditTransactionResponse{},
		},
	}
	if err := l.Write(al); err != nil {
		t.Error("failed to write to logger: ", err)
	}
	tt := time.Unix(0, ts)
	p2 := fmt.Sprintf("/%s/%s/", tt.Format("20060102"), tt.Format("20060102-1504"))
	logdir := path.Join("/tmp", p2)
	// Append the filename
	fname := fmt.Sprintf("/%s-%s", tt.Format("20060102-150405"), al.Transaction.ID)
	p := path.Join(logdir, fname)

	data, err := os.ReadFile(p)
	if err != nil {
		t.Error("failed to create audit file for concurrent logger")
		return
	}
	al2 := &AuditLog{}
	if json.Unmarshal(data, al2) != nil {
		t.Error("failed to parse json from concurrent audit log", p)
	}
}
