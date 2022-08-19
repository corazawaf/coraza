// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Logs are currently disabled for tinygo

//go:build !tinygo
// +build !tinygo

package seclang

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
)

func TestSecAuditLogDirectivesConcurrent(t *testing.T) {
	waf := coraza.NewWaf()
	auditpath := "/tmp/"
	parser, _ := NewParser(waf)
	if err := parser.FromString(`
	SecAuditLog /tmp/audit.log
	SecAuditLogFormat json
	SecAuditLogDir /tmp
	SecAuditLogDirMode 0777
	SecAuditLogFileMode 0777
	SecAuditLogType concurrent
	`); err != nil {
		t.Error(err)
	}
	id := utils.SafeRandom(10)
	if waf.AuditLogWriter == nil {
		t.Error("Invalid audit logger (nil)")
		return
	}
	if err := waf.AuditLogWriter.Write(&loggers.AuditLog{
		Parts: types.AuditLogParts("ABCDEFGHIJKZ"),
		Transaction: loggers.AuditTransaction{
			ID: id,
		},
	}); err != nil {
		t.Error(err)
	}
	f, err := findFileContaining(auditpath, id)
	if err != nil {
		t.Error(err)
	}
	data, err := os.ReadFile(f)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(data), id) {
		t.Error("failed to write audit log")
	}
	// we test it is a valid json
	var j map[string]interface{}
	if err := json.Unmarshal(data, &j); err != nil {
		t.Error(err)
	}
}

func TestDebugDirectives(t *testing.T) {
	waf := coraza.NewWaf()
	tmp := filepath.Join(t.TempDir(), "tmp.log")
	p, _ := NewParser(waf)
	err := directiveSecDebugLog(&DirectiveOptions{
		Waf:  waf,
		Opts: tmp,
	})
	if err != nil {
		t.Error(err)
	}
	if err := directiveSecDebugLogLevel(&DirectiveOptions{
		Waf:  waf,
		Opts: "5",
	}); err != nil {
		t.Error(err)
	}
	p.options.Waf.Logger.Info("abc123")
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Error(err)
	}
	if !strings.Contains(string(data), "abc123") {
		t.Errorf("failed to write info log, got %q", data)
	}
}

// Find a file by name recursively containing some string
func findFileContaining(path string, search string) (string, error) {
	files, err := os.ReadDir(path)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if file.IsDir() {
			fullpath := path + "/" + file.Name()
			file, err := findFileContaining(fullpath, search)
			if err != nil {
				return "", err
			}
			if file != "" {
				return file, nil
			}
		} else if strings.Contains(file.Name(), search) {
			return path + "/" + file.Name(), nil
		}
	}
	return "", nil
}
