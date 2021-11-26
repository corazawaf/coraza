package coraza

import (
	"regexp"
	"testing"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

func TestRuleNegativeVariables(t *testing.T) {
	rule := NewRule()
	if err := rule.AddVariable(variables.Args, "", false); err != nil {
		t.Error(err)
	}
	if rule.variables[0].Variable != variables.Args {
		t.Error("Variable not added")
	}
	if rule.variables[0].KeyRx != nil {
		t.Error("invalid key type for variable")
	}

	if err := rule.AddVariableNegation(variables.Args, "test"); err != nil {
		t.Error(err)
	}

	if len(rule.variables[0].Exceptions) != 1 || rule.variables[0].Exceptions[0].KeyStr != "test" {
		t.Errorf("got %d exceptions", len(rule.variables[0].Exceptions))
	}

	if err := rule.AddVariable(variables.Args, regexp.MustCompile("test.*"), false); err != nil {
		t.Error(err)
	}

	if rule.variables[1].KeyRx == nil || rule.variables[1].KeyRx.String() != "test.*" {
		t.Error("variable regex cannot be nil")
	}
}
