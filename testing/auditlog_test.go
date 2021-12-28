// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testing

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/loggers"
	"github.com/jptosso/coraza-waf/v2/seclang"
)

func TestAuditLogMessages(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	// generate a random tmp file
	file, err := os.CreateTemp("/tmp", "tmp*.log")
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
	tx.AddArgument("GET", "test", "test")
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
	var al2 loggers.AuditLog
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
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
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
	file, err := os.CreateTemp("/tmp", "tmp*.log")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())
	if err := parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name())); err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	if _, err := file.Seek(0, 0); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()
	var al2 loggers.AuditLog
	// this should fail, there should be no log
	if err := json.NewDecoder(file).Decode(&al2); err == nil {
		t.Error(err)
	}
}

func TestAuditLogRelevantOnlyOk(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
	// generate a random tmp file
	file, err := os.CreateTemp("/tmp", "tmp*.log")
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
	tx.AddArgument("GET", "test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	if _, err := file.Seek(0, 0); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()
	var al2 loggers.AuditLog
	// this should pass as it matches any status
	if err := json.NewDecoder(file).Decode(&al2); err != nil {
		t.Error(err)
	}
}

func TestAuditLogRelevantOnlyNoAuditlog(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
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
	file, err := os.CreateTemp("/tmp", "tmp*.log")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove(file.Name())
	if err := parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name())); err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test", "test")
	tx.ProcessRequestHeaders()
	// now we read file
	if _, err := file.Seek(0, 0); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()
	var al2 loggers.AuditLog
	// there should be no audit log because of noauditlog
	if err := json.NewDecoder(file).Decode(&al2); err == nil {
		t.Errorf("there should be no audit log, got %v", al2)
	}
}
