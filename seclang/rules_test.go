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
	"regexp"
	"strings"
	"testing"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

func TestRuleMatch(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
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

	if tx.Interruption.RuleID != 1 {
		t.Error("failed to set interruption rule id")
	}
}

func TestRuleMatchWithRegex(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
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
	} else if tx.Interruption.RuleID != 1 {
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
	tx.ProcessURI("/test.php?id=1", "get", "http/1.1")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Error(err)
	}
	tx.ProcessLogging()

	if len(tx.MatchedRules) == 0 {
		t.Error("failed to match rules")
	}

	if tx.AuditLog().Messages[0].Data.ID != 4482 {
		t.Error("failed to match rule id")
	}
}

func TestRuleLogging(t *testing.T) {
	waf := coraza.NewWaf()
	logs := []string{}
	waf.SetErrorLogCb(func(mr coraza.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS ".*" "phase:1, id:1,capture,log,setvar:'tx.arg_%{tx.0}=%{tx.0}'"
		SecAction "id:2,phase:1,log,setvar:'tx.test=ok'"
		SecAction "id:3,phase:1,nolog"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 3 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	// we expect 3 logs
	if len(logs) != 3 {
		t.Errorf("failed to log with %d", len(logs))
	} else {
		for _, l := range logs[:1] {
			if !strings.Contains(l, "[id \"1\"]") {
				t.Errorf("failed to log rule, got \n%s", l)
			}
		}
		if !strings.Contains(logs[2], "[id \"2\"]") {
			t.Errorf("failed to log rule, got \n%s", logs[2])
		}
	}
	txcol := tx.GetCollection(variables.TX)
	if txcol.GetFirstString("arg_123") != "123" || txcol.GetFirstString("arg_456") != "456" {
		t.Errorf("failed to match setvar from multiple match, got %q and %q", txcol.GetFirstString("arg_test1"), txcol.GetFirstString("arg_test2"))
	}
	if txcol.GetFirstString("test") != "ok" {
		t.Errorf("failed to match setvar from multiple match, got %q", txcol.GetFirstString("test"))
	}
}

func TestRuleChains(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS "123" "id:1,phase:1,log,chain"
			SecRule &ARGS "@gt 0" "chain"
			SecRule ARGS "456" "setvar:'tx.test=ok'"
		
		SecRule ARGS "123" "id:2,phase:1,log,chain"
			SecRule &ARGS "@gt 100" "chain"
			SecRule ARGS "456" "setvar:'tx.test2=fail'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 1 {
		t.Errorf("failed to match rules with %d matches, expected 1", len(tx.MatchedRules))
	}
	if tx.GetCollection(variables.TX).GetFirstString("test") != "ok" {
		t.Error("failed to set var")
	}
	if tx.GetCollection(variables.TX).GetFirstString("test2") == "fail" {
		t.Error("failed to set var, it shouldn't be set")
	}
}

func TestTagsAreNotPrintedTwice(t *testing.T) {
	waf := coraza.NewWaf()
	logs := []string{}
	waf.SetErrorLogCb(func(mr coraza.MatchedRule) {
		logs = append(logs, mr.ErrorLog(403))
	})
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS ".*" "phase:1, id:1,log,tag:'some1',tag:'some2'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddArgument("GET", "test1", "123")
	tx.AddArgument("GET", "test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) != 2 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	// we expect 2 logs
	if len(logs) != 2 {
		t.Errorf("failed to log with %d", len(logs))
	}
	re := regexp.MustCompile(`\[tag "some1"\]`)
	for _, l := range logs {
		if len(re.FindAllString(l, -1)) > 1 {
			t.Errorf("failed to log tag, got multiple instances (%d)\n%s", len(re.FindAllString(l, -1)), l)
		}
	}
}
