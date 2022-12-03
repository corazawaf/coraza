package config_test

import (
	"testing"

	coraza "github.com/corazawaf/coraza/v3"
)

func TestConfigRulesImmutable(t *testing.T) {
	// Add enough directives so there is enough slice capacity to reuse the array for next append.
	c := coraza.NewWAFConfig().
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRuleEngine On")

	c1 := c.WithDirectives("SecRequestBodyAccess On")

	waf1, err := coraza.NewWAF(c1)
	if err != nil {
		t.Fatal(err)
	}
	tx := waf1.NewTransaction()
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Error("Transaction for waf1 should not be interrupted")
	}

	c2 := waf1.ToConfig().WithDirectives(`SecRule ARGS:test "fail" "id:1,phase:1,deny,status:403"`)

	waf2, err := coraza.NewWAF(c2)
	if err != nil {
		t.Fatal(err)
	}
	tx2 := waf2.NewTransaction()
	tx2.ProcessURI("/test?test=fail", "GET", "HTTP/1.1")
	if it := tx2.ProcessRequestHeaders(); it == nil {
		t.Error("Transaction for waf2 should be interrupted")
	}

	tx = waf1.NewTransaction()
	tx.ProcessURI("/test?test=fail", "GET", "HTTP/1.1")
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Error("Transaction for waf2 should not be interrupted")
	}
}
