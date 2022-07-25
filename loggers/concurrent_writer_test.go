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
	"github.com/stretchr/testify/require"
)

func TestCLogFileCreation(t *testing.T) {
	file, err := ioutil.TempFile("/tmp", "tmpaudir")
	require.NoError(t, err, "failed to create concurrent logger file")

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
	err = writer.Init(config)
	require.NoError(t, err, "failed to init concurrent logger")

	err = writer.Write(al)
	require.NoError(t, err, "failed to write to logger")

	tt := time.Unix(0, ts)
	p2 := fmt.Sprintf("/%s/%s/", tt.Format("20060102"), tt.Format("20060102-1504"))
	logdir := path.Join("/tmp", p2)
	// Append the filename
	fname := fmt.Sprintf("/%s-%s", tt.Format("20060102-150405"), al.Transaction.ID)
	p := path.Join(logdir, fname)

	data, err := os.ReadFile(p)
	require.NoError(t, err, "failed to create audit file for concurrent logger")

	al2 := &AuditLog{}
	err = json.Unmarshal(data, al2)
	require.NoError(t, err, "failed to parse json from concurrent audit log")
}
