// Copyright 2021 Juan Pablo Tosso
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

package seclang

import (
	"testing"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

func TestRuleMatch(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDebugLog /tmp/coraza.log
		SecDebugLogLevel 5
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule REMOTE_ADDR "^127.*" "id:1,phase:1"
		SecRule REMOTE_ADDR "!@rx 127.0.0.1" "id:2,phase:1"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 0, "", 0)
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	if tx.Interruption == nil {
		t.Error("failed to interrupt transaction")
	}

	if tx.Interruption.RuleId != 1 {
		t.Error("failed to set interruption rule id")
	}
}

func TestRuleMatchWithRegex(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDebugLog /tmp/coraza.log
		SecDebugLogLevel 5
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule ARGS:/^id_.*/ "123" "phase:1, id:1"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "id_test", "123")
	tx.ProcessRequestHeaders()
	if tx.GetCollection(variables.Args).GetFirstString("id_test") != "123" {
		t.Error("rule variable error")
	}
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	if tx.Interruption == nil {
		t.Error("failed to interrupt transaction")
	} else if tx.Interruption.RuleId != 1 {
		t.Error("failed to set interruption rule id")
	}
}

func TestSecMarkers(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On		
		SecAction "phase:1, id:1,log,skipAfter:SoMe_TEST"
		SecAction "phase:1, id:2,deny,status:403"

		SecMarker SoMe_TEST
		SecAction "phase:2, id:3,deny,status:403,log"
	`)

	if err != nil {
		t.Error(err.Error())
	}

	if waf.Rules.Count() != 4 {
		t.Error("failed to compile some rule.")
	}

	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessRequestHeaders()
	if tx.Interrupted() {
		t.Error("transaction failed to skipAfter")
	}
	interruption, err := tx.ProcessRequestBody()
	if interruption == nil || err != nil {
		t.Error("failed to interrupt")
	}
	if len(tx.MatchedRules) == 1 {
		t.Errorf("not matching any rule after secmark")
	}
}

func TestSecAuditLogs(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecAuditEngine On
		SecAction "id:4482,log,auditlog, msg:'test'"
		SecAuditLogParts ABCDEFGHIJK
		SecRuleEngine On
	`)
	if err != nil {
		t.Error(err)
	}
	tx := waf.NewTransaction()
	tx.ProcessUri("/test.php?id=1", "get", "http/1.1")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()
	tx.ProcessLogging()

	if len(tx.MatchedRules) == 0 {
		t.Error("failed to match rules")
	}

	if tx.AuditLog().Messages[0].Data.Id != 4482 {
		t.Error("failed to match rule id")
	}
}
