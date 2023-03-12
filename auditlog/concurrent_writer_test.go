// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
)

func TestConcurrentWriterNoop(t *testing.T) {
	config := NewConfig()
	writer := &concurrentWriter{}
	if err := writer.Init(config); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	if err := writer.Close(); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestConcurrentWriterFailsOnInit(t *testing.T) {
	config := NewConfig()
	config.File = "/unexisting.log"
	config.Dir = t.TempDir()
	config.FileMode = fs.FileMode(0777)
	config.DirMode = fs.FileMode(0777)
	config.Formatter = jsonFormatter

	writer := &concurrentWriter{}
	if err := writer.Init(config); err == nil {
		t.Error("expected error")
	}
}

func TestConcurrentWriterWrites(t *testing.T) {
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Error("failed to create concurrent logger file")
	}
	config := Config{
		File:      file.Name(),
		Dir:       dir,
		FileMode:  fs.FileMode(0777),
		DirMode:   fs.FileMode(0777),
		Formatter: jsonFormatter,
	}
	ts := time.Now().UnixNano()
	al := &Log{
		Transaction: Transaction{
			UnixTimestamp: ts,
			ID:            "123",
			Request:       TransactionRequest{},
			Response:      TransactionResponse{},
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
	logdir := path.Join(dir, p2)
	// Append the filename
	fname := fmt.Sprintf("/%s-%s", tt.Format("20060102-150405"), al.Transaction.ID)
	p := path.Join(logdir, fname)

	data, err := os.ReadFile(p)
	if err != nil {
		t.Error("failed to create audit file for concurrent logger")
		return
	}
	al2 := &Log{}
	if json.Unmarshal(data, al2) != nil {
		t.Error("failed to parse json from concurrent audit log", p)
	}

	if err := writer.Close(); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}