// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"regexp"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

func TestRuleMatch(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
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
	if len(tx.MatchedRules()) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules()))
	}
	if tx.Interruption() == nil {
		t.Fatal("failed to interrupt transaction")
	}

	if tx.Interruption().RuleID != 1 {
		t.Error("failed to set interruption rule id")
	}
}

func TestRuleMatchWithRegex(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule ARGS:/^id_.*/ "123" "phase:1, id:1"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("id_test", "123")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules()) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules()))
	}
	if tx.Interruption() == nil {
		t.Error("failed to interrupt transaction")
	} else if tx.Interruption().RuleID != 1 {
		t.Error("failed to set interruption rule id")
	}
}

func TestSecMarkers(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
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
	if tx.IsInterrupted() {
		t.Error("transaction failed to skipAfter")
	}
	interruption, err := tx.ProcessRequestBody()
	if interruption == nil || err != nil {
		t.Error("failed to interrupt")
	}
	if len(tx.MatchedRules()) == 1 {
		t.Errorf("not matching any rule after secmark")
	}
}

// There can only be one disruptive action per rule (if there are multiple disruptive
// actions present, or inherited, only the last one will take effect).
// The parser enforces it, keeping only one disruptive action per rule.
func TestOnlyLastDisruptiveActionEnforced(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	// Both deny and allow are disruptive actions, so only allow should be enforced
	err := parser.FromString(`
		SecRuleEngine On
		SecDefaultAction "phase:1,deny,status:403,log"
		SecRule REQUEST_URI "@unconditionalMatch" "id:1, phase:1,deny,allow,log,auditlog"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules()) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules()))
	}
	if tx.Interruption() != nil {
		t.Fatal("unexpected interruption, deny action has been enforced instead of allow")
	}
}

func TestSecAuditLogs(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
		SecAuditEngine On
		SecAction "id:4482,log,auditlog, msg:'test'"
		SecAuditLogParts ABCDEFGHIJKZ
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

	if len(tx.MatchedRules()) == 0 {
		t.Error("failed to match rules")
	}

	if tx.AuditLog().Messages()[0].Data().ID() != 4482 {
		t.Error("failed to match rule id")
	}
}

func TestAuditLogNoLogAuditLogInteraction(t *testing.T) {
	tests := []struct {
		name              string
		actions           string
		wantErrorLog      bool
		wantAuditMessages bool
	}{
		{
			name:              "log includes rule in both error and audit log",
			actions:           "log,auditlog",
			wantErrorLog:      true,
			wantAuditMessages: true,
		},
		{
			name:              "nolog excludes rule from both logs",
			actions:           "nolog",
			wantErrorLog:      false,
			wantAuditMessages: false,
		},
		{
			name:              "nolog,auditlog includes rule in audit log only",
			actions:           "nolog,auditlog",
			wantErrorLog:      false,
			wantAuditMessages: true,
		},
		{
			name:              "log,noauditlog includes rule in error log only",
			actions:           "log,noauditlog",
			wantErrorLog:      true,
			wantAuditMessages: false,
		},
		{
			// noauditlog without explicit log on a phase 1 rule: no built-in default provides log
			// for phase 1 (only phase 2 has hardcoded defaults). Users should set SecDefaultAction
			// for other phases in coraza.conf-recommended to get log behavior.
			name:              "noauditlog without log on phase 1, no logging without SecDefaultAction",
			actions:           "noauditlog",
			wantErrorLog:      false,
			wantAuditMessages: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := corazawaf.NewWAF()
			var errorLogCount int
			waf.SetErrorCallback(func(_ types.MatchedRule) {
				errorLogCount++
			})

			parser := NewParser(waf)
			err := parser.FromString(`
				SecAuditEngine On
				SecAuditLogParts ABCDEFGHIJKZ
				SecRuleEngine On
				SecAction "id:100,phase:1,pass,` + tt.actions + `,msg:'test rule'"
			`)
			if err != nil {
				t.Fatal(err)
			}

			tx := waf.NewTransaction()
			tx.ProcessURI("/test", "GET", "HTTP/1.1")
			tx.ProcessRequestHeaders()
			if _, err := tx.ProcessRequestBody(); err != nil {
				t.Fatal(err)
			}
			tx.ProcessLogging()

			al := tx.AuditLog()
			gotAuditMessages := len(al.Messages()) > 0
			gotErrorLog := errorLogCount > 0

			if gotErrorLog != tt.wantErrorLog {
				t.Errorf("error log: got called=%v, want called=%v", gotErrorLog, tt.wantErrorLog)
			}
			if gotAuditMessages != tt.wantAuditMessages {
				t.Errorf("audit log messages: got present=%v, want present=%v", gotAuditMessages, tt.wantAuditMessages)
			}

			if err := tx.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestPhase5NoAuditLogRuleLogging validates that a phase 5 SecAction rule with noauditlog
// (but without explicit nolog) appears in the error log when SecDefaultAction provides log
// for phase 5. This matches the behavior expected from CRS rules like 980170 (Anomaly Scores)
// which use noauditlog to avoid audit log spam while still needing to appear in the error log.
// In ModSecurity, the default actionset merge provides log to all rules. In Coraza, users
// should set SecDefaultAction for phases 3-5 (as in coraza.conf-recommended) to get this behavior.
func TestPhase5NoAuditLogRuleLogging(t *testing.T) {
	waf := corazawaf.NewWAF()
	var errorLogMessages []string
	waf.SetErrorCallback(func(mr types.MatchedRule) {
		errorLogMessages = append(errorLogMessages, mr.Message())
	})

	parser := NewParser(waf)
	// Simulate CRS rule 980170: phase 5, noauditlog, no explicit log, msg with TX variable refs.
	// SecDefaultAction for phase 5 provides log (as recommended in coraza.conf-recommended).
	err := parser.FromString(`
		SecRuleEngine On
		SecAuditEngine On
		SecAuditLogParts ABCDEFGHIJKZ
		SecDefaultAction "phase:1,log,auditlog,pass"
		SecDefaultAction "phase:2,log,auditlog,pass"
		SecDefaultAction "phase:5,log,auditlog,pass"
		SecAction "id:901100,phase:1,pass,nolog,setvar:'tx.inbound_anomaly_score_threshold=5',setvar:'tx.blocking_inbound_anomaly_score=0'"
		SecRule ARGS "@rx test" "id:100,phase:2,log,pass,msg:'test',setvar:'tx.blocking_inbound_anomaly_score=+5'"
		SecAction "id:980170,phase:5,pass,t:none,noauditlog,msg:'Anomaly Score: %{tx.blocking_inbound_anomaly_score} threshold=%{tx.inbound_anomaly_score_threshold}'"
	`)
	if err != nil {
		t.Fatalf("unexpected parse error: %s", err)
	}

	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("param", "test")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal(err)
	}
	tx.ProcessLogging()

	// Rule 980170 should appear in error log (Log=true from built-in phase 5 default)
	found := false
	for _, msg := range errorLogMessages {
		if strings.Contains(msg, "Anomaly Score:") {
			found = true
			// Message should contain the expanded TX variables (not empty, not raw macros)
			if !strings.Contains(msg, "5") {
				t.Errorf("message should contain expanded score, got: %q", msg)
			}
			break
		}
	}
	if !found {
		t.Errorf("rule 980170-like phase 5 rule with noauditlog should appear in error log; error log messages: %v", errorLogMessages)
	}

	// Rule 980170 should NOT appear in audit log messages (noauditlog prevents it)
	al := tx.AuditLog()
	for _, msg := range al.Messages() {
		if msg.Data() != nil && msg.Data().ID() == 980170 {
			t.Error("rule 980170-like should NOT appear in audit log messages due to noauditlog")
		}
	}

	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuleLogging(t *testing.T) {
	waf := corazawaf.NewWAF()
	var logs []string
	waf.SetErrorCallback(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog())
	})
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS ".*" "phase:1, id:1,capture,log,setvar:'tx.arg_%{tx.0}=%{tx.0}'"
		SecAction "id:2,phase:1,log,setvar:'tx.test=ok'"
		SecAction "id:3,phase:1,nolog"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test1", "123")
	tx.AddGetRequestArgument("test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules()) != 3 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules()))
	}
	// we expect 2 logs
	if len(logs) != 2 {
		t.Errorf("failed to log with %d", len(logs))
	} else {
		for _, l := range logs[:1] {
			if !strings.Contains(l, "[id \"1\"]") {
				t.Errorf("failed to log rule, got \n%s", l)
			}
		}
		if !strings.Contains(logs[1], "[id \"2\"]") {
			t.Errorf("failed to log rule, got \n%s", logs[2])
		}
	}
}

func TestRuleChains(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
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
	tx.AddGetRequestArgument("test1", "123")
	tx.AddGetRequestArgument("test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules()) != 1 {
		t.Errorf("failed to match rules with %d matches, expected 1", len(tx.MatchedRules()))
	}
}

func TestChainStarterDisruptiveActionFires(t *testing.T) {
	// The starter rule's disruptive action must interrupt the transaction when the
	// full chain matches, and must NOT fire when the chain does not match.
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	if err := parser.FromString(`
		SecRuleEngine On
		SecRule ARGS "@rx attack" "id:1,phase:1,deny,status:403,log,chain"
			SecRule &ARGS "@gt 0" ""
	`); err != nil {
		t.Fatalf("unexpected parse error: %s", err)
	}

	t.Run("chain matches — interruption expected", func(t *testing.T) {
		tx := waf.NewTransaction()
		tx.AddGetRequestArgument("payload", "attack")
		tx.ProcessRequestHeaders()
		if tx.Interruption() == nil {
			t.Error("expected interruption from chain starter deny, got nil")
		} else if tx.Interruption().RuleID != 1 {
			t.Errorf("expected interruption from rule 1, got rule %d", tx.Interruption().RuleID)
		}
	})

	t.Run("chain does not match — no interruption", func(t *testing.T) {
		tx := waf.NewTransaction()
		tx.AddGetRequestArgument("payload", "benign")
		tx.ProcessRequestHeaders()
		if tx.Interruption() != nil {
			t.Errorf("expected no interruption, got one from rule %d", tx.Interruption().RuleID)
		}
	})
}

func TestTagsAreNotPrintedTwice(t *testing.T) {
	waf := corazawaf.NewWAF()
	var logs []string
	waf.SetErrorCallback(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog())
	})
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS ".*" "phase:1, id:1,log,tag:'some1',tag:'some2'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test1", "123")
	tx.AddGetRequestArgument("test2", "456")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules()) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules()))
	}
	// we expect 1 log
	if len(logs) != 1 {
		t.Errorf("failed to log with %d", len(logs))
	}
	re := regexp.MustCompile(`\[tag "some1"\]`)
	for _, l := range logs {
		if len(re.FindAllString(l, -1)) > 1 {
			t.Errorf("failed to log tag, got multiple instances (%d)\n%s", len(re.FindAllString(l, -1)), l)
		}
	}
}

func TestPrintedExtraMsgAndDataFromRuleWithMultipleMatches(t *testing.T) {
	waf := corazawaf.NewWAF()
	var logs []string
	waf.SetErrorCallback(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog())
	})
	parser := NewParser(waf)
	err := parser.FromString(`
	SecRule ARGS_GET "@rx .*" "id:1, phase:1, log, pass, logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "1")
	tx.AddGetRequestArgument("test2", "2")
	tx.ProcessRequestHeaders()
	if len(logs) != 1 {
		t.Errorf("failed to log. Expected 1 entry, got %d", len(logs))
	}
	if count := strings.Count(logs[0], "2 in ARGS_GET:test2"); count != 1 {
		t.Errorf("failed to log logdata, expected %q occurrence(s), got %v", "2 in ARGS_GET:test2", logs[0])
	}
	if count := strings.Count(logs[0], "1 in ARGS_GET:test"); count != 1 {
		t.Errorf("failed to log second logdata, expected %q occurrence(s), got %v", "1 in ARGS_GET:test", logs[0])
	}
}
func TestPrintedExtraMsgAndDataFromChainedRules(t *testing.T) {
	waf := corazawaf.NewWAF()
	var logs []string
	waf.SetErrorCallback(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog())
	})
	parser := NewParser(waf)
	err := parser.FromString(`
	SecRule ARGS_GET "@rx .*" "id:1, phase:1, log, chain, deny, status:403, msg:'Parent msg', logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}"
	  SecRule ARGS_GET "@rx .*" "msg:'Inner message 1', logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}', chain"
	    SecRule ARGS_GET "@rx .*" "msg:'Inner message 2', logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "1")
	it := tx.ProcessRequestHeaders()
	if it == nil {
		t.Error("failed to interrupt")
	} else if it.Status != 403 {
		t.Errorf("failed to set status, got %d", it.Status)
	}
	if len(logs) != 1 {
		t.Errorf("failed to log. Expected 1 entry, got %d", len(logs))
	}
	if count := strings.Count(logs[0], "1 in ARGS_GET:test"); count != 3 {
		t.Errorf("failed to log logdata, expected 3 repetitions, got %d", count)
	}
	if count := strings.Count(logs[0], "Inner message 1"); count != 1 {
		t.Errorf("Unexpected number of msg from inner rule 1, expected 1 got %d", count)
	}
	if count := strings.Count(logs[0], "Inner message 2"); count != 1 {
		t.Errorf("Unexpected number of msg from inner rule 2, expected 1 got %d", count)
	}
}

func TestPrintedMultipleMsgAndDataWithMultiMatch(t *testing.T) {
	waf := corazawaf.NewWAF()
	var logs []string
	waf.SetErrorCallback(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog())
	})
	parser := NewParser(waf)
	err := parser.FromString(`
	SecRule ARGS_GET "@rx .*" "id:9696, phase:1, log, deny, t:lowercase, status:403, msg:'msg', logdata:'%{MATCHED_VAR} in %{MATCHED_VAR_NAME}',multiMatch"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("testArgGet", "tEsT1")
	it := tx.ProcessRequestHeaders()
	if it == nil {
		t.Error("failed to interrupt")
	} else if it.Status != 403 {
		t.Errorf("failed to set status, got %d", it.Status)
	}
	if len(logs) != 1 {
		t.Errorf("failed to log with %d", len(logs))
	}
	if count := strings.Count(logs[0], "tEsT1 in ARGS_GET"); count != 1 {
		t.Errorf("failed to log logdata, expected \"tEsT1 in ARGS_GET\" occurrence, got %s", logs[0])
	}
	if count := strings.Count(logs[0], "test1 in ARGS_GET"); count != 1 {
		t.Errorf("failed to log logdata, expected \"test1 in ARGS_GET\" occurrence, got %s", logs[0])
	}
}

func TestStatusFromInterruptions(t *testing.T) {
	waf := corazawaf.NewWAF()
	var logs []string
	waf.SetErrorCallback(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog())
	})
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS "123" "phase:1, id:1,log,deny,status:500"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test1", "123")
	tx.AddGetRequestArgument("test2", "456")
	it := tx.ProcessRequestHeaders()
	if it == nil {
		t.Error("failed to interrupt")
	} else if it.Status != 500 {
		t.Errorf("failed to set status, got %d", it.Status)
	}
}

func TestChainWithUnconditionalMatch(t *testing.T) {
	waf := corazawaf.NewWAF()
	p := NewParser(waf)
	if err := p.FromString(`
	SecAction "id:7, pass, phase:1, log, chain, skip:2"
    SecRule REMOTE_ADDR "@unconditionalMatch" ""
	`); err != nil {
		t.Error(err)
	}
	if waf.Rules.Count() != 1 {
		t.Errorf("invalid rule count, got %d", waf.Rules.Count())
	}
}

func TestLogsAreNotPrintedManyTimes(t *testing.T) {
	waf := corazawaf.NewWAF()
	var logs []string
	waf.SetErrorCallback(func(mr types.MatchedRule) {
		logs = append(logs, mr.ErrorLog())
	})
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRule ARGS|REQUEST_HEADERS|!ARGS:test1 ".*" "phase:1, id:1,log,tag:'some1',tag:'some2'"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test1", "123")
	tx.AddGetRequestArgument("test2", "456")
	tx.AddGetRequestArgument("test2", "789")
	tx.AddRequestHeader("test", "123")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules()) != 1 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules()))
	}
	// we expect 2 logs
	if len(logs) != 1 {
		t.Errorf("failed to log with %d", len(logs))
	}
}

func TestSampleRxRule(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
	SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "phase:1,id:1,log,deny,status:403,chain"
	SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$"`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/test", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Content-Length", "15")
	if it := tx.ProcessRequestHeaders(); it == nil {
		t.Error("failed to interrupt")
	}
}

func TestTxIssue147(t *testing.T) {
	// https://github.com/corazawaf/coraza/issues/147
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`SecRule RESPONSE_BODY "@rx ^#!\s?/" "id:950140,phase:4,log,deny,status:403"`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	// response body access is required
	tx.ResponseBodyAccess = true
	tx.WAF.ResponseBodyMimeTypes = []string{"text/html"}
	tx.AddResponseHeader("Content-Type", "text/html")
	tx.ProcessRequestHeaders()
	_, _ = tx.ProcessRequestBody()
	tx.ProcessResponseHeaders(200, "HTTP/1.1")

	if tx.IsResponseBodyProcessable() {
		if it, _, err := tx.WriteResponseBody([]byte("#!/usr/bin/python")); it != nil || err != nil {
			t.Error(err)
		}

		it, err := tx.ProcessResponseBody()
		if err != nil {
			t.Error(err)
		}
		if it != nil {
			httpOutMsg := ""
			for _, res := range tx.MatchedRules() {
				httpOutMsg = httpOutMsg + res.MatchedDatas()[0].Key() + ":" + res.MatchedDatas()[0].Value() + "\n"
				httpOutMsg = httpOutMsg + "Message:" + res.MatchedDatas()[0].Message() + "\n"

			}
			if len(httpOutMsg) == 0 || len(tx.MatchedRules()) == 0 {
				t.Error("failed to log")
			}
		} else {
			t.Error("failed to block response body")
		}
	} else {
		t.Error("failed to process response body")
	}
}

func TestIssue176(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule REQUEST_COOKIES:sessionId "test" "id:1,phase:1,deny,log,msg:'test rule',logdata:'Matched %{MATCHED_VAR_NAME}'"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Cookie", "sessionId=test")
	it := tx.ProcessRequestHeaders()
	if it == nil {
		t.Error("error test for github issue #176")
	}

	// 	Test for argument case-sensitive
	//	err = parser.FromString(`
	//		SecRule ARGS:Test1 "123" "id:3,phase:1,log,deny"
	//	`)
	//	if err != nil {
	//		t.Error(err.Error())
	//	}
	//	tx = waf.NewTransaction()
	//	tx.AddGetRequestArgument("Test1", "123")
	//	it = tx.ProcessRequestHeaders()
	//	if it == nil {
	//		t.Error("failed to test argument case-sensitive")
	//	}
	//
	//	err = parser.FromString(`
	//		SecRule ARGS:test2 "123" "id:5,phase:1,log,deny"
	//	`)
	//	if err != nil {
	//		t.Error(err.Error())
	//	}
	//	tx = waf.NewTransaction()
	//	tx.AddGetRequestArgument("Test2", "123")
	//	it = tx.ProcessRequestHeaders()
	//	if it != nil {
	//		t.Error("failed to test argument case-sensitive")
	//	}
}

func TestRxCapture(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule &TX:allowed_request_content_type_charset "@eq 0" \
        "id:901168,\
        phase:1,\
        pass,\
        nolog,\
        ver:'OWASP_CRS/3.4.0-dev',\
        setvar:'tx.allowed_request_content_type_charset=|utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|'"
    SecRule REQUEST_HEADERS:Content-Type "@rx charset\s*=\s*[\"']?([^;\"'\s]+)" \
        "id:920480,\
        phase:1,\
        deny,\
        capture,\
        t:none,\
        msg:'Request content type charset is not allowed by policy',\
        logdata:'%{MATCHED_VAR}',\
        tag:'application-multi',\
        tag:'language-multi',\
        tag:'platform-multi',\
        tag:'attack-protocol',\
        tag:'paranoia-level/1',\
        tag:'OWASP_CRS',\
        tag:'capec/1000/255/153',\
        tag:'PCI/12.1',\
        ver:'OWASP_CRS/3.4.0-dev',\
        severity:'CRITICAL',\
        setvar:'tx.content_type_charset=|%{tx.1}|',\
        chain"
        SecRule TX:content_type_charset "!@within %{tx.allowed_request_content_type_charset}" \
            "t:lowercase,\
            ctl:forceRequestBodyVariable=On,\
            setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Content-Type", "text/html; charset=utf-8")
	it := tx.ProcessRequestHeaders()
	if it != nil {
		t.Error("failed test for rx captured")
	}
}

func TestUnicode(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule ARGS "@rx \x{30cf}\x{30ed}\x{30fc}" "id:101,phase:2,t:lowercase,deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.AddPostRequestArgument("var", `ハローワールド`)
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("non utf-8 rx test fails")
	}
}

func Test941310(t *testing.T) {
	// TODO(anuraaga): Go regex only supports utf8 strings. This means to match non-utf8 would require escaping the
	// input into ASCII before matching. Just the presence of a non-utf8 matcher, like in CRS, would cause this escaping
	// to be required on all input. This is probably not worth it performance-wise, as with Go few HTTP libraries would
	// support non-utf8 anyways.

	// not supported on TinyGo
	// t.Skip("non-utf8 regex not supported")

	// waf := corazawaf.NewWAF()
	// rules := `SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx \xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe" \
	// "id:941310,\
	// phase:2,\
	// deny,\
	// capture,\
	// t:none,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode,\
	// msg:'US-ASCII Malformed Encoding XSS Filter - Attack Detected',\
	// logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
	// tag:'application-multi',\
	// tag:'language-multi',\
	// tag:'platform-tomcat',\
	// tag:'attack-xss',\
	// tag:'paranoia-level/1',\
	// tag:'OWASP_CRS',\
	// tag:'capec/1000/152/242',\
	// ver:'OWASP_CRS/3.4.0-dev',\
	// severity:'CRITICAL',\
	// chain"
	// SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx (?:\xbc\s*/\s*[^\xbe>]*[\xbe>])|(?:<\s*/\s*[^\xbe]*\xbe)" \
	//     "t:none,t:lowercase,t:urlDecode,t:htmlEntityDecode,t:jsDecode,\
	//     ctl:auditLogParts=+E,\
	//     setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
	//     setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"`
	// parser := NewParser(waf)
	//
	// err := parser.FromString(rules)
	// if err != nil {
	// 	t.Error()
	// 	return
	// }
	//
	// tx := waf.NewTransaction()
	// tx.AddPostRequestArgument("var", `\\xbcscript\\xbealert(\xa2XSS\xa2)\xbc/script\xbe`)
	// it, err := tx.ProcessRequestBody()
	// if err != nil {
	// 	t.Error(err)
	// }
	// if it == nil {
	// 	t.Error("non utf-8 rx test fails")
	// }
}

func TestArgumentNamesCaseSensitive(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule ARGS_NAMES "Test1" "id:3, phase:2, log, deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}
	/*
		tx := waf.NewTransaction()
		tx.AddPostRequestArgument("Test1", "Xyz")
		it, err := tx.ProcessRequestBody()
		if err != nil {
			t.Error(err)
		}
		if it == nil {
			t.Error("failed to test argument names case sensitive: same case nomatch")
		}

		tx = waf.NewTransaction()
		tx.AddPostRequestArgument("TEST1", "Xyz")
		it, err = tx.ProcessRequestBody()
		if err != nil {
			t.Error(err)
		}
		if it != nil {
			t.Error("failed to test argument names case sensitive: Upper case argument name matched")
		}

		tx = waf.NewTransaction()
		tx.AddPostRequestArgument("test1", "Xyz")
		it, err = tx.ProcessRequestBody()
		if err != nil {
			t.Error(err)
		}
		if it != nil {
			t.Error("failed to test argument names case sensitive: Lower case argument name matched")
		}
	*/
}

func TestCookiesCaseSensitive(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule REQUEST_COOKIES:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.AddRequestHeader("cookie", "Test1=Xyz")
	tx.ProcessRequestHeaders()
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction()
	tx.AddRequestHeader("cookie", "TEST1=Xyz")
	tx.ProcessRequestHeaders()
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction()
	tx.AddRequestHeader("cookie", "test1=Xyz")
	tx.ProcessRequestHeaders()
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction()
	tx.AddRequestHeader("cookie", "test1=xyz")
	tx.ProcessRequestHeaders()
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test cookies value case sensitive")
	}

	tx = waf.NewTransaction()
	tx.AddRequestHeader("cookie", "test1=XYZ")
	tx.ProcessRequestHeaders()
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test cookies value case sensitive")
	}
}

func TestHeadersCaseSensitive(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule REQUEST_HEADERS:Test1 "Xyz" "id:3, phase:2, log, deny"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Test1", "Xyz")
	tx.ProcessRequestHeaders()
	it, err := tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction()
	tx.AddRequestHeader("TEST1", "Xyz")
	tx.ProcessRequestHeaders()
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction()
	tx.AddRequestHeader("test1", "Xyz")
	tx.ProcessRequestHeaders()
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it == nil {
		t.Error("failed to test cookies case sensitive")
	}

	tx = waf.NewTransaction()
	tx.AddRequestHeader("test1", "xyz")
	tx.ProcessRequestHeaders()
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test cookies value case sensitive")
	}

	tx = waf.NewTransaction()
	tx.AddRequestHeader("test1", "XYZ")
	tx.ProcessRequestHeaders()
	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if it != nil {
		t.Error("failed to test cookies value case sensitive")
	}
}

// HPP - Detect HTTP Parameter Pollution Attacks
// Parameter pollution attacks are a type of attack where the attacker tries to manipulate the parameters of a request
// to bypass security controls, or to cause unexpected behavior. This rule is designed to detect parameter pollution
// The following test will test the parameter pollution with the following rule:
// SecRule ARGS:test1 "xyz" "id:3, phase:2, log, pass"
// Attack:
// POST /test?test1=xyz
// test1=abc&test1=ZZZZ
// In this case, the attacker tries to send three different values for the same parameter, and the rule should still match.
// Coraza should add the matched parameter to an array and iterate over it to check for matches.
func TestSingleParameterPollution(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule ARGS:test1 "xyz" "id:3, phase:2, log, pass"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.AddPostRequestArgument("test1", "xyz")
	tx.AddPostRequestArgument("test1", "abc")
	tx.AddPostRequestArgument("test1", "ZZZZ")
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules()) == 1 {
		if len(tx.MatchedRules()[0].MatchedDatas()) != 1 {
			t.Errorf("failed to test arguments pollution. Found matches: %d, %+v\n",
				len(tx.MatchedRules()[0].MatchedDatas()), tx.MatchedRules())
		}
	} else {
		t.Errorf("failed to test arguments pollution: Single match fixed case: %d, %+v\n",
			len(tx.MatchedRules()), tx.MatchedRules())
	}
}

// HPP - Detect HTTP Parameter Pollution Attacks
// This test case uses two rules instead of one to test the parameter pollution. The rules are:
// 1. SecRule ARGS:test1 "xyz" "id:3, phase:2, log, pass"
// 2. SecRule ARGS:test1 "ZZZZ" "id:4, phase:2, log, pass"
// Attack:
// POST /test?test1=xyz&test1=ABCD
// test1=abc&test1=ZZZZ
// In this case, the attacker tries to send multiple different values for the same parameter, and the rule should match in
// both cases. Coraza should add the matched parameter to an array and iterate over it to check for matches.`
// For the above case, the rule should match twice.
func TestMultipleParameterPollution(t *testing.T) {
	rules := `SecRule ARGS:test1 "xyz" "id:3, phase:2, log, pass"
SecRule ARGS:test1 "ZZZZ" "id:4, phase:2, log, pass"`
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test1", "xyz")
	tx.AddGetRequestArgument("test1", "ABCD")
	tx.ProcessRequestHeaders()
	tx.AddPostRequestArgument("test1", "abc")
	tx.AddPostRequestArgument("test1", "ZZZZ")
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}
	if len(tx.MatchedRules()) == 2 {
		if len(tx.MatchedRules()[0].MatchedDatas()) != 1 {
			t.Errorf("failed to test first argument pollution. Found matches: %d, %+v\n",
				len(tx.MatchedRules()[0].MatchedDatas()), tx.MatchedRules())
		}
		if len(tx.MatchedRules()[1].MatchedDatas()) != 1 {
			t.Errorf("failed to test second match pollution. Found matches: %d, %+v\n",
				len(tx.MatchedRules()[0].MatchedDatas()), tx.MatchedRules())
		}
	} else {
		t.Errorf("failed to test arguments pollution, less matches than expected: %d", len(tx.MatchedRules()))
	}
}

func TestURIQueryParamNameCaseSensitive(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `SecRule ARGS_NAMES "Test1" "id:3, phase:2, log, pass"`
	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Error()
		return
	}

	tx := waf.NewTransaction()
	tx.ProcessURI("/url?Test1='SQLI", "POST", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules()) == 1 {
		if len(tx.MatchedRules()[0].MatchedDatas()) != 1 {
			t.Errorf("failed to test uri query param. Expected: 1, Found matches: %d, %+v\n",
				len(tx.MatchedRules()[0].MatchedDatas()), tx.MatchedRules())
		}
		if !isMatchData(tx.MatchedRules()[0].MatchedDatas(), "Test1") {
			t.Error("Key did not match: Test1 !=", tx.MatchedRules()[0])
		}
	} else {
		t.Errorf("failed to test uri query param: Same case arg name:%d, %+v\n",
			len(tx.MatchedRules()), tx.MatchedRules())
	}

	tx = waf.NewTransaction()
	tx.ProcessURI("/test?test1='SQLI&Test1='SQLI&TEST1='SQLI", "POST", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	_, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
	}

	if len(tx.MatchedRules()) == 1 {
		if len(tx.MatchedRules()[0].MatchedDatas()) != 1 {
			t.Errorf("Failed to test uri query param. Expected: 1, Found matches: %d, %+v\n",
				len(tx.MatchedRules()[0].MatchedDatas()), tx.MatchedRules())
		}
		if !isMatchData(tx.MatchedRules()[0].MatchedDatas(), "Test1") {
			t.Error("Key did not match: Test1 !=", tx.MatchedRules()[0])
		}
	} else {
		t.Error("failed to test qparam pollution: Multiple arg different case:",
			len(tx.MatchedRules()))
	}
}

func isMatchData(mds []types.MatchData, key string) (result bool) {
	result = false
	for _, m := range mds {
		if m.Key() == key {
			result = true
			break
		}
	}
	return result
}

func TestEscapedQuoteInOperator(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecRule ARGS:id "@contains \"" "id:1,phase:1,deny,status:403,log,auditlog"
	`)
	if err != nil {
		t.Fatal(err)
	}

	// Positive: request with a double quote in id should be blocked
	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("id", `1"`)
	it := tx.ProcessRequestHeaders()
	if it == nil {
		t.Error("expected transaction to be interrupted for request containing a double quote")
	} else if it.RuleID != 1 {
		t.Errorf("expected rule ID 1, got %d", it.RuleID)
	}

	// Negative: request without a double quote should not be blocked
	tx = waf.NewTransaction()
	tx.AddGetRequestArgument("id", "1")
	it = tx.ProcessRequestHeaders()
	if it != nil {
		t.Error("unexpected interruption for request without a double quote")
	}
}

func Test930110_10(t *testing.T) {
	waf := corazawaf.NewWAF()
	rules := `
SecRequestBodyAccess On
SecRule REQUEST_URI|ARGS|REQUEST_HEADERS|!REQUEST_HEADERS:Referer|FILES|XML:/* "@rx (?:(?:^|[\x5c/])\.{2,3}[\x5c/]|[\x5c/]\.{2,3}(?:[\x5c/]|$))" \
    "id:930110,\
    phase:2,\
    deny,\
    capture,\
    t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,t:cmdLine,\
    msg:'Path Traversal Attack (/../) or (/.../)',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-lfi',\
    tag:'paranoia-level/1',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/255/153/126',\
    ver:'OWASP_CRS/3.4.0-dev',\
    severity:'CRITICAL',\
    multiMatch,\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}',\
    setvar:'tx.lfi_score=+%{tx.critical_anomaly_score}'"
`

	parser := NewParser(waf)

	err := parser.FromString(rules)
	if err != nil {
		t.Fatal(err)
		return
	}

	tx := waf.NewTransaction()
	tx.AddRequestHeader("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryABCDEFGIJKLMNOPQ")
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Errorf("Unexpected interruption with status %d at Request Headers phaseus\n", it.Status)
	}

	body := strings.NewReader(`
------WebKitFormBoundaryABCDEFGIJKLMNOPQ
Content-Disposition: form-data; name="file"; filename="../1.7z"
Content-Type: application/octet-stream

BINARYDATA
------WebKitFormBoundaryABCDEFGIJKLMNOPQ--`)
	it, _, err := tx.ReadRequestBodyFrom(body)
	if err != nil {
		t.Error(err)
		return
	}

	if it != nil {
		t.Fatal(err)
	}

	it, err = tx.ProcessRequestBody()
	if err != nil {
		t.Error(err)
		return
	}
	if it == nil {
		t.Error("failed test for rx captured")
	}
}
