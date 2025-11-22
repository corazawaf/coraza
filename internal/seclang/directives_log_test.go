// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

// Logs are currently disabled for tinygo builds.
package seclang

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
)

func TestSecAuditLogDirectivesConcurrent(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)

	auditpath := t.TempDir()
	if err := parser.FromString(fmt.Sprintf(`
	SecAuditLog %s
	SecAuditLogFormat json
	SecAuditLogDir %s
	SecAuditLogDirMode 0777
	SecAuditLogFileMode 0777
	SecAuditLogType concurrent
	`, filepath.Join(auditpath, "audit.log"), auditpath)); err != nil {
		t.Fatal(err)
	}

	id := utils.RandomString(10)

	if err := waf.AuditLogWriter().Write(&auditlog.Log{
		Parts_: types.AuditLogParts("ABCDEFGHIJKZ"),
		Transaction_: auditlog.Transaction{
			ID_: id,
		},
	}); err != nil {
		t.Fatal(err)
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
	waf := corazawaf.NewWAF()
	tmp := filepath.Join(t.TempDir(), "tmp.log")
	p := NewParser(waf)
	err := directiveSecDebugLog(&DirectiveOptions{
		WAF:  waf,
		Opts: tmp,
	})
	if err != nil {
		t.Error(err)
	}
	if err := directiveSecDebugLogLevel(&DirectiveOptions{
		WAF:  waf,
		Opts: "3",
	}); err != nil {
		t.Error(err)
	}
	p.options.WAF.Logger.Info().Msg("abc123")
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
