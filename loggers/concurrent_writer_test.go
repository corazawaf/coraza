// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

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

	"github.com/corazawaf/coraza/v3/types"
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
