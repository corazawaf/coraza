package parser

import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func TestString(t *testing.T) {
	rule := `SecRule ARGS:/(.*?)/|REQUEST_HEADERS:/X-(Coraza|\w+)/ "@rx (.*?)" "id:1, drop, phase: 1"`
	waf := &engine.Waf{}
	waf.Init()
	p := &Parser{}
	p.Init(waf)
	p.Evaluate(rule)
	
	if len(waf.Rules.GetRules()) != 1{
		t.Error("Rule not created")
	}
	r := waf.Rules.GetRules()[0]
	if len(r.Actions) != 3{
		t.Error("Failed to parse actions")
	}
	if len(r.Variables) != 2{
		t.Error("Failed to parse variables")
	}
	if r.Variables[1].Key != `/X-(Coraza|\w+)/`{
		t.Error("Invalid variable key for regex")
	}
}

/*
* Directives
* TODO There should be an elegant way to separate them from the parser
*/

