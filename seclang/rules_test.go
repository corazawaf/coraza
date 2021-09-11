package seclang

import (
	"testing"

	"github.com/jptosso/coraza-waf"
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
	if tx.GetCollection(coraza.VARIABLE_ARGS).GetFirstString("id_test") != "123" {
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

func TestRuleMatchCaseSensitivity(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	err := parser.FromString(`
		SecRuleEngine On
		SecDebugLog /tmp/coraza.log
		SecDebugLogLevel 5
		SecDefaultAction "phase:1,deny,status:403,log"
		# shouldnt match
		SecRule REQUEST_HEADERS "^SomEthing$" "id:1,phase:1"
		SecRule &REQUEST_HEADERS:User-AgenT "@eq 0" "phase:1, id:2,deny,status:403"
		SecRule REQUEST_HEADERS:user-Agent "some" "phase:2, id:3,deny,status:403"
	`)
	if err != nil {
		t.Error(err.Error())
	}
	tx := waf.NewTransaction()
	tx.AddRequestHeader("user-Agent", "something")
	tx.ProcessRequestHeaders()
	if len(tx.MatchedRules) > 0 {
		t.Errorf("failed to match rules with %d", len(tx.MatchedRules))
	}
	if tx.Interruption != nil {
		t.Error("failed transaction was interrupted")
	}

	if it, _ := tx.ProcessRequestBody(); it == nil {
		t.Error("transaction wasn't interrupted")
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
