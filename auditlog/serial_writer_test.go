// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

func TestSerialLoggerFailsOnInit(t *testing.T) {
	config := types.Config{}
	writer := &serialWriter{}
	if err := writer.Init(config); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	if err := writer.Close(); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestSerialWriterFailsOnInit(t *testing.T) {
	config := types.Config{
		"auditlog_file":      "/unexisting.log",
		"auditlog_dir":       t.TempDir(),
		"auditlog_file_mode": fs.FileMode(0777),
		"auditlog_dir_mode":  fs.FileMode(0777),
		"auditlog_formatter": jsonFormatter,
	}
	writer := &serialWriter{}
	if err := writer.Init(config); err == nil {
		t.Error("expected error")
	}
}

func TestSerialWriterWrites(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.log")
	writer := &serialWriter{}
	config := types.Config{
		"auditlog_file":      tmp,
		"auditlog_formatter": jsonFormatter,
	}
	if err := writer.Init(config); err != nil {
		t.Error(err)
	}
	al := &Log{
		Transaction: Transaction{
			ID: "test123",
		},
		Messages: []Message{
			{
				Data: MessageData{
					ID:  100,
					Raw: "SecAction \"id:100\"",
				},
			},
		},
	}
	if err := writer.Write(al); err != nil {
		t.Error("failed to write to serial logger")
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Error("failed to read serial logger file", err)
	}
	if !strings.Contains(string(data), "test123") {
		t.Errorf("failed to parse log tx id from serial log: \n%q on file %q", string(data), tmp)
	}
	if !strings.Contains(string(data), "id:100") {
		t.Errorf("failed to parse log rule id: \n%q on file %q", string(data), tmp)
	}

	if err := writer.Close(); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}
