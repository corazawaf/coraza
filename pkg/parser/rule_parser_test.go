package parser

import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func TestDefaultActions(t *testing.T){
	waf := engine.NewWaf()
	p := NewParser(waf)
	err := p.AddDefaultActions("log, pass, phase: 1")
	if err != nil{
		t.Error("Error parsing default actions", err)
	}
	if len(p.GetDefaultActions()) == 0 {
		t.Error("Default actions were not created")
	}

	r, err := p.ParseRule(`ARGS "test" "id:1"`)
	if err != nil {
		t.Error("Failed to parse rule", err)
	}

	if r.DefaultDisruptiveAction != "pass"{
		t.Error("Failed to assign default disruptive rule to action, currently " + r.DefaultDisruptiveAction)
	}
}