// Copyright 2022 Juan Pablo Tosso
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
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v2/types"
)

func TestCLogFileCreation(t *testing.T) {
	file, err := ioutil.TempFile("/tmp", "tmpaudir")
	if err != nil {
		t.Error("failed to create concurrent logger file")
	}
	config := types.Config{
		"auditlog_file":      file.Name(),
		"auditlog_dir":       "/tmp",
		"auditlog_file_mode": fs.FileMode(0777),
		"auditlog_dir_mode":  fs.FileMode(0777),
		"auditlog_formatter": jsonFormatter,
	}
	ts := time.Now().UnixNano()
	al := &AuditLog{
		Transaction: AuditTransaction{
			UnixTimestamp: ts,
			ID:            "123",
			Request:       AuditTransactionRequest{},
			Response:      AuditTransactionResponse{},
		},
	}
	writer := &concurrentWriter{}
	if err := writer.Init(config); err != nil {
		t.Error("failed to init concurrent logger", err)
	}
	if err := writer.Write(al); err != nil {
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
