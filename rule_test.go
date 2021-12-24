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

package coraza

import (
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

	if err := rule.AddVariable(variables.Args, "/test.*/", false); err != nil {
		t.Error(err)
	}

	if rule.variables[1].KeyRx == nil || rule.variables[1].KeyRx.String() != "test.*" {
		t.Error("variable regex cannot be nil")
	}
}

func TestVariableKeysAreCaseInsensitive(t *testing.T) {
	rule := NewRule()
	if err := rule.AddVariable(variables.Args, "Som3ThinG", false); err != nil {
		t.Error(err)
	}
	if rule.variables[0].KeyStr != "som3thing" {
		t.Error("variable key is not case insensitive")
	}
}

func TestVariablesRxAreCaseSensitive(t *testing.T) {
	rule := NewRule()
	if err := rule.AddVariable(variables.Args, "/Som3ThinG/", false); err != nil {
		t.Error(err)
	}
	if rule.variables[0].KeyRx.String() != "Som3ThinG" {
		t.Error("variable key is not case insensitive")
	}
}
