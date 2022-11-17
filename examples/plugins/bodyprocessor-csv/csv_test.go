package plugin

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
)

var csvPayload = `id,name,age
1,foo,10
2,bar,20
3,juan,30
`

func TestCSV(t *testing.T) {
	cfg := coraza.NewWAFConfig().WithDirectives(`
	SecRuleEngine On
	SecRequestBodyAccess On
	SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=CSV"
	SecRule ARGS_POST:/CSV\.\d+\.name/ "jose", "id:2, phase:2, deny, log, msg:'Jose is not allowed >:C'"
	SecRule ARGS_POST:/CSV\.\d+\.name/ "juan", "id:3, phase:2, deny, log, msg:'Juan is not allowed >:C'"
	`)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	if _, err := tx.RequestBodyWriter().Write([]byte(csvPayload)); err != nil {
		t.Fatal(err)
	}
	tx.ProcessRequestHeaders()
	if it, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	} else if it == nil {
		t.Fatal("expected interruption")
	}
	if len(tx.MatchedRules()) != 2 {
		t.Fatalf("expected 1 rule to match, got %d", len(tx.MatchedRules()))
	}
	if tx.MatchedRules()[1].Rule().ID() != 3 {
		t.Fatalf("expected rule 3 to match, got %d", tx.MatchedRules()[1].Rule().ID())
	}
}
