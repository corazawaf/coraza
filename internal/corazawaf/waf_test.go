// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/types"
)

func TestNewTransaction(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyAccess = true
	waf.ResponseBodyAccess = true
	waf.RequestBodyLimit = 1044

	tx := waf.NewTransactionWithOptions(Options{ID: "test"})
	if !tx.RequestBodyAccess {
		t.Error("Request body access not enabled")
	}
	if !tx.ResponseBodyAccess {
		t.Error("Response body access not enabled")
	}
	if tx.RequestBodyLimit != 1044 {
		t.Error("Request body limit not set")
	}
	if tx.id != "test" {
		t.Error("ID not set")
	}
	tx = waf.NewTransactionWithOptions(Options{ID: ""})
	if tx.id == "" {
		t.Error("ID not set")
	}
	tx = waf.NewTransaction()
	if tx.id == "" {
		t.Error("ID not set")
	}
}

func TestNewTransactionWithOptionsID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		keep bool
	}{
		{name: "random string", id: "SojdH8AAQEAAAugAQAAAAAA", keep: true},
		{name: "uuid", id: "5f0c6a9e-8f4b-4f6e-9d55-0b1a2c3d4e5f", keep: true},
		{name: "dots and colons", id: "..:edge.example:1234..", keep: true},
		{name: "non ascii", id: "trace-ñ-1", keep: true},
		{name: "path traversal", id: "../../../../ESCAPED"},
		{name: "absolute path", id: "/etc/cron.d/x"},
		{name: "backslash", id: `..\..\ESCAPED`},
		{name: "line feed", id: "a\nEVIL 1.2.3.4 - - [forged]"},
		{name: "carriage return", id: "a\rb"},
		{name: "nul", id: "a\x00b"},
		{name: "del", id: "a\x7fb"},
	}

	waf := NewWAF()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := waf.NewTransactionWithOptions(Options{ID: tt.id})
			defer tx.Close()
			if tt.keep {
				if tx.id != tt.id {
					t.Errorf("want id %q, have %q", tt.id, tx.id)
				}
				return
			}
			if tx.id == tt.id || !isValidTransactionID(tx.id) || len(tx.id) != 19 {
				t.Errorf("want a generated id instead of %q, have %q", tt.id, tx.id)
			}
		})
	}
}

func TestNewTransactionWithOptionsDoesNotLogRejectedID(t *testing.T) {
	const id = "sensitive-token/child"
	logs := &bytes.Buffer{}
	waf := NewWAF()
	waf.Logger = debuglog.Default().WithLevel(debuglog.LevelWarn).WithOutput(logs)

	tx := waf.NewTransactionWithOptions(Options{ID: id})
	defer tx.Close()

	if got := logs.String(); strings.Contains(got, id) {
		t.Errorf("warning contains rejected transaction ID: %q", got)
	} else if !strings.Contains(got, "generating a new one") {
		t.Errorf("missing replacement warning: %q", got)
	}
}

func TestNewTransactionResetsDetectionOnlyInterruption(t *testing.T) {
	waf := NewWAF()

	// A transaction that recorded a detection-only interruption, then returned
	// to the pool via Close().
	tx := waf.NewTransaction()
	tx.detectionOnlyInterruption = &types.Interruption{Status: 403}
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	// A subsequent transaction reuses the pooled object and must not inherit it.
	reused := waf.NewTransaction()
	if reused.IsDetectionOnlyInterrupted() {
		t.Error("detectionOnlyInterruption leaked from a pooled transaction into a reused one")
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSetDebugLogPath(t *testing.T) {
	tests := map[string]struct {
		path string
		w    io.Writer
	}{
		"empty path": {path: "", w: io.Discard},
		"stdout":     {path: "/dev/stdout", w: os.Stdout},
		"stderr":     {path: "/dev/stderr", w: os.Stderr},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			w, err := resolveLogPath(test.path)
			if err != nil {
				t.Errorf("unexpected error: %s", err.Error())
			}

			if w != test.w {
				t.Errorf("expected io.Discard, got %T", w)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	testCases := map[string]struct {
		customizer func(*WAF)
		expectErr  bool
	}{
		"default": {
			expectErr:  false,
			customizer: func(w *WAF) {},
		},
		"request body limit less than zero": {
			expectErr:  true,
			customizer: func(w *WAF) { w.RequestBodyLimit = -1 },
		},
		"request body limit greater than 1gib": {
			expectErr:  true,
			customizer: func(w *WAF) { w.RequestBodyLimit = _1gib + 1 },
		},
		"request body in memory limit less than zero": {
			expectErr:  true,
			customizer: func(w *WAF) { w.SetRequestBodyInMemoryLimit(-1) },
		},
		"request body limit less than request body in memory limit": {
			expectErr: true,
			customizer: func(w *WAF) {
				w.RequestBodyLimit = 10
				w.SetRequestBodyInMemoryLimit(11)
			}},
		"response body limit less than zero": {
			expectErr:  true,
			customizer: func(w *WAF) { w.ResponseBodyLimit = -1 },
		},
		"response body limit greater than 1gib": {
			expectErr:  true,
			customizer: func(w *WAF) { w.ResponseBodyLimit = _1gib + 1 },
		},
		"argument limit greater than 0": {
			expectErr:  false,
			customizer: func(w *WAF) { w.ArgumentLimit = 1000 },
		},
		"argument limit less than 0": {
			expectErr:  true,
			customizer: func(w *WAF) { w.ArgumentLimit = -1 },
		},
	}

	if environment.HasAccessToFS {
		testCases["upload keep files on without upload dir"] = struct {
			customizer func(*WAF)
			expectErr  bool
		}{
			expectErr: true,
			customizer: func(w *WAF) {
				w.UploadKeepFiles = types.UploadKeepFilesOn
				w.UploadDir = ""
			},
		}
		testCases["upload keep files relevant only without upload dir"] = struct {
			customizer func(*WAF)
			expectErr  bool
		}{
			expectErr: true,
			customizer: func(w *WAF) {
				w.UploadKeepFiles = types.UploadKeepFilesRelevantOnly
				w.UploadDir = ""
			},
		}
		testCases["upload keep files on with upload dir"] = struct {
			customizer func(*WAF)
			expectErr  bool
		}{
			expectErr: false,
			customizer: func(w *WAF) {
				w.UploadKeepFiles = types.UploadKeepFilesOn
				w.UploadDir = "/tmp"
			},
		}
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			waf := NewWAF()
			tCase.customizer(waf)
			err := waf.Validate()
			if tCase.expectErr {
				if err == nil {
					t.Fatalf("expected error: %s", err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			}
		})
	}
}
