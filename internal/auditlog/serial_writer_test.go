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

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestSerialLoggerFailsOnInit(t *testing.T) {
	config := NewConfig()
	writer := &serialWriter{}
	if err := writer.Init(config); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	if err := writer.Close(); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestSerialWriterFailsOnInit(t *testing.T) {
	config := NewConfig()
	config.File = "/unexisting.log"
	config.Dir = t.TempDir()
	config.FileMode = fs.FileMode(0777)
	config.DirMode = fs.FileMode(0777)
	config.Formatter = jsonFormatter

	writer := &serialWriter{}
	if err := writer.Init(config); err == nil {
		t.Error("expected error")
	}
}

func TestSerialWriterWrites(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.log")
	writer := &serialWriter{}
	config := NewConfig()
	config.File = tmp
	config.Formatter = jsonFormatter

	if err := writer.Init(config); err != nil {
		t.Error(err)
	}
	al := &Log{
		Transaction_: Transaction{
			ID_: "test123",
		},
		Messages_: []plugintypes.AuditLogMessage{
			Message{
				Data_: &MessageData{
					ID_:  100,
					Raw_: "SecAction \"id:100\"",
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
