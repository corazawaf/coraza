package crs

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"testing"
)

func TestCrs(t *testing.T) {
	waf := engine.NewWaf()
	c, err := NewCrs("", waf)
	if err == nil {
		t.Error("Should fail with invalid path")
	}

	c, err = NewCrs("../../docs/crs/rules/", waf)
	if err != nil {
		t.Error("Should not fail with valid path")
		return
	}

	err = c.Build()
	if err != nil {
		t.Error("Failed to build rules", err)
	}
	l := len(waf.Rules.GetRules())

	if l == 0 {
		t.Error("No rules found")
	}

	if l < 500 {
		t.Error("Not enough CRS rules, found ", l)
	}	
}
