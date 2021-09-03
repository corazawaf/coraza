package seclang

import (
	"strconv"
	"strings"
	"testing"

	"github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/plugins"
	"github.com/jptosso/coraza-waf/transformations"
)

func init() {
	plugins.RegisterTransformation("testToLower", transformationToLowercase)
	plugins.RegisterOperator("even", func() coraza.Operator {
		return &opEven{}
	})
	plugins.RegisterAction("id15", func() coraza.RuleAction {
		return &id15{}
	})
}

// Test transformation, string to lowercase

func transformationToLowercase(input string, _ *transformations.Tools) string {
	return strings.ToLower(input)
}

// Test action, set ID to 15

type id15 struct{}

func (id15) Init(rule *coraza.Rule, _ string) error {
	rule.Id = 15
	return nil
}

func (id15) Evaluate(_ *coraza.Rule, _ *coraza.Transaction) {}

func (id15) Type() int {
	return coraza.ACTION_TYPE_DATA
}

// Test operator, match if number is even

type opEven struct{}

func (opEven) Init(_ string) error {
	return nil
}

func (opEven) Evaluate(_ *coraza.Transaction, input string) bool {
	i, _ := strconv.Atoi(input)
	return i%2 == 0
}

// Tripwires

var _ transformations.Transformation = transformationToLowercase
var _ coraza.RuleAction = &id15{}
var _ coraza.Operator = &opEven{}

func TestPlugins(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := NewParser(waf)
	if err := parser.FromString("SecRule ARGS \"@even\" \"id15,log\""); err != nil {
		t.Error(err)
	}

	if waf.Rules.GetRules()[0].Id != 15 {
		t.Error("failed to set rule id to 15")
	}

	if !waf.Rules.GetRules()[0].Operator.Operator.Evaluate(nil, "2") {
		t.Error("failed to match operator even")
	}

	if waf.Rules.GetRules()[0].Operator.Operator.Evaluate(nil, "1") {
		t.Error("failed to match operator even")
	}
}
