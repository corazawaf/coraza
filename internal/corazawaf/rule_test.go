// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"testing"

	"github.com/corazawaf/coraza/v3/macro"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestSecActionMessagePropagationInMatchData(t *testing.T) {
	r := NewRule()
	r.Msg, _ = macro.NewMacro("Message")
	r.LogData, _ = macro.NewMacro("Data Message")
	r.ID_ = 1
	// SecAction uses nil operator
	r.operator = nil
	tx := NewWAF().NewTransaction()
	transformationCache := tx.transformationCache
	matchdata := r.doEvaluate(types.PhaseLogging, tx, transformationCache)
	if len(matchdata) != 1 {
		t.Errorf("expected 1 matchdata from a SecActions rule, got %d", len(matchdata))
	}

	if want, have := r.Msg.String(), matchdata[0].Message(); want != have {
		t.Fatalf("unexpected Message: want %q, have %q", want, have)
	}
	if want, have := r.LogData.String(), matchdata[0].Data(); want != have {
		t.Fatalf("unexpected LogData: want %q, have %q", want, have)
	}
}

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

func TestInferredPhase(t *testing.T) {
	var b inferredPhases

	if b.has(types.PhaseRequestHeaders) ||
		b.has(types.PhaseRequestBody) ||
		b.has(types.PhaseResponseHeaders) ||
		b.has(types.PhaseResponseBody) {
		t.Error("unexpected phase")
	}

	b.set(types.PhaseRequestHeaders)
	if !b.has(types.PhaseRequestHeaders) {
		t.Error("expected to have phase")
	}

	b.set(types.PhaseRequestBody)
	if !b.has(types.PhaseRequestBody) {
		t.Error("expected to have phase")
	}

	b.set(types.PhaseResponseHeaders)
	if !b.has(types.PhaseResponseHeaders) {
		t.Error("expected to have phase")
	}

	b.set(types.PhaseResponseBody)
	if !b.has(types.PhaseResponseBody) {
		t.Error("expected to have phase")
	}
}
