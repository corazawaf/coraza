// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package auditlog

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestSerialLoggerSuccessOnInit(t *testing.T) {
	tests := map[string]struct {
		target         string
		expectedCloser io.Closer
	}{
		"empty": {
			expectedCloser: NoopCloser,
		},
		"stderr": {
			target:         "/dev/stderr",
			expectedCloser: NoopCloser,
		},
		"stdout": {
			target:         "/dev/stdout",
			expectedCloser: NoopCloser,
		},
	}
	for name, test := range tests {
		config := NewConfig()
		config.Target = test.target

		w := &serialWriter{}
		t.Run(name, func(t *testing.T) {
			if err := w.Init(config); err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}

			if want, have := test.expectedCloser, w.Closer; want != have {
				t.Errorf("unexpected closer, want %v, have %v", want, have)
			}

			if err := w.Close(); err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}
		})
	}
}

func TestSerialWriterFailsOnInitForUnexistingFile(t *testing.T) {
	config := NewConfig()
	config.Target = "/unexisting.log"
	config.Dir = t.TempDir()
	config.FileMode = fs.FileMode(0777)
	config.DirMode = fs.FileMode(0777)
	config.Formatter = jsonFormatter

	w := &serialWriter{}
	if err := w.Init(config); err == nil {
		t.Error("expected error")
	}

	if err := w.Close(); err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
}

func TestSerialWriterWrites(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.log")
	writer := &serialWriter{}
	config := NewConfig()
	config.Target = tmp
	config.Formatter = jsonFormatter

	if err := writer.Init(config); err != nil {
		t.Fatal(err)
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
		t.Fatal("failed to read serial logger file", err)
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
