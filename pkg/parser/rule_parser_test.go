package parser

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"testing"
)

func TestDefaultActions(t *testing.T) {
	waf := engine.NewWaf()
	p, _ := NewParser(waf)
	err := p.AddDefaultActions("log, pass, phase: 1")
	if err != nil {
		t.Error("Error parsing default actions", err)
	}
	p.AddDefaultActions("log, drop, phase:2")
	if len(p.GetDefaultActions()) != 2 {
		t.Error("Default actions were not created")
	}

	r, err := p.ParseRule(`ARGS "test" "id:1"`)
	if err != nil {
		t.Error("Failed to parse rule", err)
	}
	if r.DefaultDisruptiveAction != "pass" {
		t.Error("Failed to assign default disruptive rule to action, currently " + r.DefaultDisruptiveAction)
	}
	r2, _ := p.ParseRule(`ARGS "test" "phase:2,id:2"`)

	if r2.DefaultDisruptiveAction != "drop" {
		t.Error("Failed to assign default disruptive rule to action, currently " + r.DefaultDisruptiveAction)
	}
}
