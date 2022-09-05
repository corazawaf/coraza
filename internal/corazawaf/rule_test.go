// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestRuleNegativeVariables(t *testing.T) {
	rule := NewRule()
	if err := rule.AddVariable(variables.Args, "", false); err != nil {
		t.Error(err)
	}
	if rule.variables[0].Variable != variables.Args {
		t.Error("Variable ARGS was not added")
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
