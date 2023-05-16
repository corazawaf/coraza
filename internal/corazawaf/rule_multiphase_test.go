// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build coraza.rule.multiphase_evaluation

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestARGSSplit(t *testing.T) {
	rule := NewRule()
	key := "something"
	if err := rule.AddVariable(variables.Args, key, false); err != nil {
		t.Error(err)
	}
	if len(rule.variables) != 2 {
		t.Fatalf("Expected 2 variables, got %d", len(rule.variables))
	}
	if rule.variables[0].Variable != variables.ArgsGet &&
		rule.variables[1].Variable != variables.ArgsPost {
		t.Errorf("Expected variables ArgsGet and ArgsPost")
	}
	if rule.variables[0].KeyStr != key && rule.variables[1].KeyStr != key {
		t.Errorf("Expected keys equal to %s, got: %s and %s", key, rule.variables[0].KeyStr, rule.variables[1].KeyStr)
	}
}

func TestARGS_NAMESSplit(t *testing.T) {
	rule := NewRule()
	key := "name"
	if err := rule.AddVariable(variables.ArgsNames, key, false); err != nil {
		t.Error(err)
	}
	if len(rule.variables) != 2 {
		t.Fatalf("Expected 2 variables, got %d", len(rule.variables))
	}
	if rule.variables[0].Variable != variables.ArgsGetNames &&
		rule.variables[1].Variable != variables.ArgsPostNames {
		t.Errorf("Expected ArgsGetNames and ArgsPostNames variables")
	}
	if rule.variables[0].KeyStr != key && rule.variables[1].KeyStr != key {
		t.Errorf("Expected keys equal to %s, got: %s and %s", key, rule.variables[0].KeyStr, rule.variables[1].KeyStr)
	}
}

func TestRuleNegativeVariablesMulti(t *testing.T) {
	rule := NewRule()
	if err := rule.AddVariable(variables.Args, "", false); err != nil {
		t.Error(err)
	}
	// [0] ArgsGet
	// [1] ArgsPost
	if rule.variables[0].Variable != variables.ArgsGet && rule.variables[1].Variable != variables.ArgsPost {
		t.Error("Variable ARGS has not been properly added and splitted into ArgsPost ArgsGet")
	}
	if rule.variables[0].KeyRx != nil && rule.variables[1].KeyRx != nil {
		t.Error("invalid key type for variables")
	}

	if err := rule.AddVariableNegation(variables.Args, "test"); err != nil {
		t.Error(err)
	}

	if len(rule.variables[0].Exceptions) != 1 || rule.variables[0].Exceptions[0].KeyStr != "test" {
		t.Errorf("got %d exceptions, expected 1", len(rule.variables[0].Exceptions))
	}

	if len(rule.variables[1].Exceptions) != 1 || rule.variables[1].Exceptions[0].KeyStr != "test" {
		t.Errorf("got %d exceptions, expected 1", len(rule.variables[0].Exceptions))
	}

	if err := rule.AddVariable(variables.Args, "/test.*/", false); err != nil {
		t.Error(err)
	}
	// [0] ArgsGet name (1 exception)
	// [1] ArgsPost name (1 exception)
	// [2] ArgsGet regex
	// [3] ArgsPost regex
	if rule.variables[2].KeyRx == nil || rule.variables[2].KeyRx.String() != "test.*" {
		t.Error("variable regex cannot be nil")
	}
	if rule.variables[3].KeyRx == nil || rule.variables[3].KeyRx.String() != "test.*" {
		t.Error("variable regex cannot be nil")
	}

	// [0] ArgsGet name (2 exceptions)
	// [1] ArgsPost name (2 exceptions)
	// [2] ArgsGet regex (1 exception)
	// [3] ArgsPost regex (1 exception)
	if err := rule.AddVariableNegation(variables.Args, "test2"); err != nil {
		t.Error(err)
	}

	if len(rule.variables[0].Exceptions) != 2 || rule.variables[0].Exceptions[1].KeyStr != "test2" {
		t.Errorf("got %d exceptions, expected 2", len(rule.variables[0].Exceptions))
	}

	if len(rule.variables[1].Exceptions) != 2 || rule.variables[1].Exceptions[1].KeyStr != "test2" {
		t.Errorf("got %d exceptions, expected 2", len(rule.variables[0].Exceptions))
	}

	if len(rule.variables[2].Exceptions) != 1 || rule.variables[0].Exceptions[1].KeyStr != "test2" {
		t.Errorf("got %d exceptions, expected 2", len(rule.variables[0].Exceptions))
	}

	if len(rule.variables[3].Exceptions) != 1 || rule.variables[0].Exceptions[1].KeyStr != "test2" {
		t.Errorf("got %d exceptions, expected 2", len(rule.variables[0].Exceptions))
	}

}
