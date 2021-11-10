// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testing

import (
	"strconv"
	"strings"
	"testing"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/actions"
	seclang "github.com/jptosso/coraza-waf/v2/seclang"
)

func init() {
	actions.RegisterRuleAction("id15", func() coraza.RuleAction {
		return &id15{}
	})
}

// Test transformation, string to lowercase

func transformationToLowercase(input string, _ coraza.RuleTransformationTools) string {
	return strings.ToLower(input)
}

// Test action, set ID to 15

type id15 struct{}

func (id15) Init(rule *coraza.Rule, _ string) error {
	rule.Id = 15
	return nil
}

func (id15) Evaluate(_ *coraza.Rule, _ *coraza.Transaction) {}

func (id15) Type() coraza.RuleActionType {
	return coraza.ActionTypeData
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

var _ coraza.RuleTransformation = transformationToLowercase
var _ coraza.RuleAction = &id15{}
var _ coraza.RuleOperator = &opEven{}

func TestPlugins(t *testing.T) {
	waf := coraza.NewWaf()
	parser, _ := seclang.NewParser(waf)
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
