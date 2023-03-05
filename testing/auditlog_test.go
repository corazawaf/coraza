// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Audit logs are currently disabled for tinygo

//go:build !tinygo
// +build !tinygo

package testing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/corazawaf/coraza/v3/auditlog"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
)

func TestAuditLogMessages(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	// generate a random tmp file
	file, err := os.Create(filepath.Join(t.TempDir(), "tmp.log"))
	if err != nil {
		t.Error(err)
	}
	if err := parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name())); err != nil {
		t.Error(err)
	}
	if err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,msg:'unconditional match'"
	`); err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	al := tx.AuditLog()
	if len(al.Messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(al.Messages))
	}
	if al.Messages[0].Message != "unconditional match" {
		t.Errorf("Expected message 'unconditional match', got '%s'", al.Messages[0].Message)
	}
	tx.ProcessLogging()
	// now we read file
	if _, err := file.Seek(0, 0); err != nil {
		t.Error(err)
	}
	var al2 auditlog.Log
	if err := json.NewDecoder(file).Decode(&al2); err != nil {
		t.Error(err)
	}
	if len(al2.Messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(al2.Messages))
	}
	if al2.Messages[0].Message != "unconditional match" {
		t.Errorf("Expected message %q, got %q", "unconditional match", al2.Messages[0].Message)
	}
}

func TestAuditLogRelevantOnly(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	if err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus 401
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,msg:'unconditional match'"
	`); err != nil {
		t.Error(err)
	}
	// generate a random tmp file
	file, err := os.Create(filepath.Join(t.TempDir(), "tmp.log"))
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())
	if err := parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name())); err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	if _, err := file.Seek(0, 0); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()
	var al2 auditlog.Log
	// this should fail, there should be no log
	if err := json.NewDecoder(file).Decode(&al2); err == nil {
		t.Error(err)
	}
}

func TestAuditLogRelevantOnlyOk(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	// generate a random tmp file
	file, err := os.Create(filepath.Join(t.TempDir(), "tmp.log"))
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())
	if err := parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name())); err != nil {
		t.Error(err)
	}
	if err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus ".*"
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,log,msg:'unconditional match'"
	`); err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	if _, err := file.Seek(0, 0); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()
	var al2 auditlog.Log
	// this should pass as it matches any status
	if err := json.NewDecoder(file).Decode(&al2); err != nil {
		t.Error(err)
	}
}

func TestAuditLogRelevantOnlyNoAuditlog(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	if err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine RelevantOnly
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogRelevantStatus ".*"
		SecRule ARGS "@unconditionalMatch" "id:1,phase:1,noauditlog,msg:'unconditional match'"
	`); err != nil {
		t.Error(err)
	}
	// generate a random tmp file
	file, err := os.Create(filepath.Join(t.TempDir(), "tmp.log"))
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())
	if err := parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name())); err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	if _, err := file.Seek(0, 0); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()
	var al2 auditlog.Log
	// there should be no audit log because of noauditlog
	if err := json.NewDecoder(file).Decode(&al2); err == nil {
		t.Errorf("there should be no audit log, got %v", al2)
	}
}
