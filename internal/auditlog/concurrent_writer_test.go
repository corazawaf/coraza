// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
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
	config.Target = "/unexisting.log"
	config.Dir = t.TempDir()
	config.FileMode = fs.FileMode(0777)
	config.DirMode = fs.FileMode(0777)
	config.Formatter = &jsonFormatter{}

	writer := &concurrentWriter{}
	if err := writer.Init(config); err == nil {
		t.Error("expected error")
	}
}

type mockFormatter struct {
	plugintypes.AuditLogFormatter
	formatted []byte
	err       error
}

func (ef mockFormatter) Format(plugintypes.AuditLog) ([]byte, error) {
	return ef.formatted, ef.err
}

func TestConcurrentWriter(t *testing.T) {
	t.Run("empty formatted", func(t *testing.T) {
		config := plugintypes.AuditLogConfig{
			Target:    os.DevNull,
			Formatter: mockFormatter{},
		}

		writer := &concurrentWriter{}
		if err := writer.Init(config); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if err := writer.Write(nil); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("formatting error", func(t *testing.T) {
		config := plugintypes.AuditLogConfig{
			Target:    os.DevNull,
			Formatter: mockFormatter{err: errors.New("formatting error")},
		}

		writer := &concurrentWriter{}
		if err := writer.Init(config); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if err := writer.Write(nil); err == nil {
			t.Errorf("expected error: %v", err)
		}
	})
}

func TestConcurrentWriterSuccess(t *testing.T) {
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Error("failed to create concurrent logger file")
	}
	config := plugintypes.AuditLogConfig{
		Target:    file.Name(),
		Dir:       dir,
		FileMode:  fs.FileMode(0777),
		DirMode:   fs.FileMode(0777),
		Formatter: &jsonFormatter{},
	}
	if err := file.Close(); err != nil {
		t.Error(err)
	}

	writer := &concurrentWriter{}
	if err := writer.Init(config); err != nil {
		t.Error("failed to init concurrent logger", err)
	}
	defer writer.Close()

	ts := time.Now()
	expectedLog := &Log{
		Transaction_: Transaction{
			UnixTimestamp_: ts.UnixNano(),
			ID_:            "123",
			Request_: &TransactionRequest{
				Method_:      "GET",
				URI_:         "/test",
				HTTPVersion_: "HTTP/1.1",
			},
			Response_: &TransactionResponse{
				Status_: 201,
			},
		},
	}
	if err := writer.Write(expectedLog); err != nil {
		t.Error("failed to write to logger: ", err)
	}

	fileName := fmt.Sprintf("/%s-%s", ts.Format("20060102-150405"), expectedLog.Transaction().ID())
	logFile := filepath.Join(dir, ts.Format("20060102"), ts.Format("20060102-1504"), fileName)

	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Error("failed to create audit file for concurrent logger")
		return
	}

	actualLog := &Log{}
	if err := json.Unmarshal(logData, actualLog); err != nil {
		t.Errorf("failed to parse json from concurrent audit log: %s", err.Error())
	}

	expectedLogStr, _ := json.Marshal(expectedLog)
	if !reflect.DeepEqual(expectedLog, actualLog) {
		t.Errorf("unexpected log entry, want:\n%s, have:\n%s", expectedLogStr, logData)
	}
}
