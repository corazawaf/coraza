// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"errors"
	"strconv"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestMatchEvaluate(t *testing.T) {
	r := NewRule()
	r.Msg, _ = macro.NewMacro("Message")
	r.LogData, _ = macro.NewMacro("Data Message")
	r.ID_ = 1
	if err := r.AddVariable(variables.ArgsGet, "", false); err != nil {
		t.Error(err)
	}
	dummyEqOp := &dummyEqOperator{}
	r.SetOperator(dummyEqOp, "@eq", "0")
	action := &dummyDenyAction{}
	_ = r.AddAction("dummyDeny", action)
	tx := NewWAF().NewTransaction()
	tx.AddGetRequestArgument("test", "0")

	matchdata := r.doEvaluate(types.PhaseLogging, tx, tx.transformationCache)
	if len(matchdata) != 1 {
		t.Errorf("Expected 1 matchdata from a SecActions rule, got %d", len(matchdata))
	}
	if tx.interruption == nil {
		t.Errorf("Expected interruption triggered")
	}
}

func TestNoMatchEvaluate(t *testing.T) {
	r := NewRule()
	r.ID_ = 1
	if err := r.AddVariable(variables.ArgsGet, "", false); err != nil {
		t.Error(err)
	}
	dummyEqOp := &dummyEqOperator{}
	r.SetOperator(dummyEqOp, "@eq", "1")
	action := &dummyDenyAction{}
	_ = r.AddAction("dummyDeny", action)
	tx := NewWAF().NewTransaction()
	tx.AddGetRequestArgument("test", "999")

	matchdata := r.doEvaluate(types.PhaseLogging, tx, tx.transformationCache)
	if len(matchdata) != 0 {
		t.Errorf("Expected 0 matchdata from a SecActions rule, got %d", len(matchdata))
	}
	if tx.interruption != nil {
		t.Errorf("Unexpected interruption triggered")
	}
}

func TestNoMatchEvaluateBecauseOfException(t *testing.T) {
	r := NewRule()
	r.Msg, _ = macro.NewMacro("Message")
	r.LogData, _ = macro.NewMacro("Data Message")
	r.ID_ = 1
	if err := r.AddVariable(variables.ArgsGet, "", false); err != nil {
		t.Error(err)
	}
	dummyEqOp := &dummyEqOperator{}
	r.SetOperator(dummyEqOp, "@eq", "0")
	action := &dummyDenyAction{}
	_ = r.AddAction("dummyDeny", action)
	tx := NewWAF().NewTransaction()
	tx.AddGetRequestArgument("test", "0")
	tx.RemoveRuleTargetByID(1, variables.ArgsGet, "test")
	matchdata := r.doEvaluate(types.PhaseLogging, tx, tx.transformationCache)
	if len(matchdata) != 0 {
		t.Errorf("Expected 0 matchdata, got %d", len(matchdata))
	}
	if tx.interruption != nil {
		t.Errorf("Expected interruption not triggered because of RemoveRuleTargetByID")
	}
}

type dummyFlowAction struct{}

func (*dummyFlowAction) Init(_ plugintypes.RuleMetadata, _ string) error {
	return nil
}

func (*dummyFlowAction) Evaluate(_ plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.(*Transaction).Logdata = "flow action triggered"
}

func (*dummyFlowAction) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeFlow
}

func TestFlowActionIfDetectionOnlyEngine(t *testing.T) {
	r := NewRule()
	r.ID_ = 1
	r.operator = nil
	action := &dummyFlowAction{}
	_ = r.AddAction("dummyFlowAction", action)
	tx := NewWAF().NewTransaction()
	tx.RuleEngine = types.RuleEngineDetectionOnly

	matchdata := r.doEvaluate(types.PhaseLogging, tx, tx.transformationCache)
	if len(matchdata) != 1 {
		t.Errorf("Expected 1 matchdata, got %d", len(matchdata))
	}
	if tx.Logdata != "flow action triggered" {
		t.Errorf("Expected flow action triggered with DetectionOnly engine")
	}
}

type dummyNonDisruptiveAction struct{}

func (*dummyNonDisruptiveAction) Init(_ plugintypes.RuleMetadata, _ string) error {
	return nil
}

func (*dummyNonDisruptiveAction) Evaluate(_ plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	tx.(*Transaction).Logdata = "action enforced"
}

func (*dummyNonDisruptiveAction) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeNondisruptive
}

func TestMatchVariableRunsActionTypeNondisruptive(t *testing.T) {
	rule := NewRule()
	tx := NewWAF().NewTransaction()
	md := &corazarules.MatchData{}
	action := &dummyNonDisruptiveAction{}
	_ = rule.AddAction("dummyNonDisruptiveAction", action)
	rule.matchVariable(tx, md)
	if tx.Logdata != "action enforced" {
		t.Errorf("Expected non disruptive action to be enforced during matchVariable")
	}
}

func TestDisruptiveActionFromChainNotEvaluated(t *testing.T) {
	r := NewRule()
	r.ID_ = 1
	r.operator = nil
	r.HasChain = true
	action := &dummyNonDisruptiveAction{}
	_ = r.AddAction("dummyNonDisruptiveAction", action)
	chainedRule := NewRule()
	chainedRule.ID_ = 0
	chainedRule.ParentID_ = 1
	chainedRule.operator = nil
	chainedAction := &dummyDenyAction{}
	_ = chainedRule.AddAction("dummyDenyAction", chainedAction)
	r.Chain = chainedRule
	tx := NewWAF().NewTransaction()

	matchdata := r.doEvaluate(types.PhaseLogging, tx, tx.transformationCache)
	if len(matchdata) != 2 {
		t.Errorf("Expected 2 matchdata from a SecActions chained rule (total 2 rules), got %d", len(matchdata))
	}
	if tx.interruption != nil {
		t.Errorf("Unexpected execution of a deny action that is not at the top level of the chain")
	}
}

func TestRuleDetailsTransferredToTransaction(t *testing.T) {
	r := NewRule()
	r.ID_ = 0
	r.ParentID_ = 1
	r.Capture = true
	r.operator = nil
	tx := NewWAF().NewTransaction()

	r.doEvaluate(types.PhaseLogging, tx, tx.transformationCache)
	if tx.variables.rule.Get("id")[0] != strconv.Itoa(r.ParentID()) {
		t.Errorf("Expected id: %d (parent id), got %s", r.ParentID(), tx.variables.rule.Get("id")[0])
	}
	if tx.Capture != r.Capture {
		t.Errorf("Expected tx.Capture: %t, got %t", r.Capture, tx.Capture)
	}
}

type dummyEqOperator struct{}

func (*dummyEqOperator) Evaluate(_ plugintypes.TransactionState, value string) bool {
	return value == "0"
}

func TestSecActionMessagePropagationInMatchData(t *testing.T) {
	r := NewRule()
	r.Msg, _ = macro.NewMacro("Message")
	r.LogData, _ = macro.NewMacro("Data Message")
	r.ID_ = 1
	// SecAction uses nil operator
	r.operator = nil
	tx := NewWAF().NewTransaction()
	matchdata := r.doEvaluate(types.PhaseLogging, tx, tx.transformationCache)
	if len(matchdata) != 1 {
		t.Errorf("Expected 1 matchdata from a SecActions rule, got %d", len(matchdata))
	}

	if want, have := r.Msg.String(), matchdata[0].Message(); want != have {
		t.Fatalf("Unexpected Message: want %q, have %q", want, have)
	}
	if want, have := r.LogData.String(), matchdata[0].Data(); want != have {
		t.Fatalf("Unexpected LogData: want %q, have %q", want, have)
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

func TestRuleNegativeVariablesEmtpyRule(t *testing.T) {
	var rule *Rule
	if err := rule.AddVariableNegation(variables.ArgsGet, "test"); err == nil {
		t.Error("Expected error, calling AddVariableNegation for an undefined rule")
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
		t.Error("Unexpected phase")
	}

	b.set(types.PhaseRequestHeaders)
	if !b.has(types.PhaseRequestHeaders) {
		t.Error("Expected to have phase")
	}

	b.set(types.PhaseRequestBody)
	if !b.has(types.PhaseRequestBody) {
		t.Error("Expected to have phase")
	}

	b.set(types.PhaseResponseHeaders)
	if !b.has(types.PhaseResponseHeaders) {
		t.Error("Expected to have phase")
	}

	b.set(types.PhaseResponseBody)
	if !b.has(types.PhaseResponseBody) {
		t.Error("Expected to have phase")
	}
}

type dummyDenyAction struct{}

func (*dummyDenyAction) Init(_ plugintypes.RuleMetadata, _ string) error {
	return nil
}

func (*dummyDenyAction) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	rid := r.ID()
	if rid == 0 {
		rid = r.ParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
		RuleID: rid,
		Action: "deny",
	})
}

func (*dummyDenyAction) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

func TestAddAction(t *testing.T) {
	actionName := "action_name"
	rule := NewRule()

	action := &dummyDenyAction{}
	_ = rule.AddAction(actionName, action)

	if rule.actions == nil {
		t.Fatal("Missing action after AddAction")
	}
	if rule.actions[0].Name != actionName {
		t.Errorf("Expected %s, got %s", actionName, rule.actions[0].Name)
	}
	if rule.actions[0].Function != action {
		t.Errorf("Expected %v, got %v", rule.actions[0].Function, action)
	}

}

func TestAddTransformation(t *testing.T) {
	rule := NewRule()
	transformationName := "transformation"
	transformation := func(input string) (string, bool, error) {
		return "Test", true, nil
	}
	err := rule.AddTransformation(transformationName, transformation)
	if err != nil {
		t.Fatalf("Failed to add a transformation: %s", err.Error())
	}
	if rule.transformations == nil {
		t.Fatal("Missing transformation after AddTransformation")
	}
}

func TestAddTransformationEmpty(t *testing.T) {
	rule := NewRule()
	transformationName := ""
	transformation := func(input string) (string, bool, error) {
		return transformationName, true, nil
	}
	err := rule.AddTransformation(transformationName, transformation)
	if err == nil {
		t.Fatalf("Expected error adding a transformation with empty name")
	}
}

func TestClearTransformation(t *testing.T) {
	rule := NewRule()
	transformationName := "trans"
	transformation := func(input string) (string, bool, error) {
		return transformationName, true, nil
	}
	_ = rule.AddTransformation(transformationName, transformation)
	if rule.transformations == nil {
		t.Fatal("Missing transformation after AddTransformation")
	}
	rule.ClearTransformations()
	if len(rule.transformations) > 0 {
		t.Fatal("Expected empty transformations slice after ClearTransformations")
	}
}

var transformationAppendA = func(input string) (string, bool, error) {
	return input + "A", true, nil
}

var transformationAppendB = func(input string) (string, bool, error) {
	return input + "B", true, nil
}

func TestExecuteTransformations(t *testing.T) {
	rule := NewRule()
	_ = rule.AddTransformation("AppendA", transformationAppendA)
	_ = rule.AddTransformation("AppendB", transformationAppendB)
	transformedInput, error := rule.executeTransformations("input")
	if error != nil {
		t.Fatalf("Unexecpted errors executing transformations: %v", error)
	}
	if transformedInput != "inputAB" {
		t.Fatalf("Expected inputAB, got %s", transformedInput)
	}
}

var transformationErrorA = func(input string) (string, bool, error) {
	return "", false, errors.New("errorA")
}
var transformationErrorB = func(input string) (string, bool, error) {
	return "", false, errors.New("errorB")
}

func TestExecuteTransformationsReturnsMultipleErrors(t *testing.T) {
	rule := NewRule()
	_ = rule.AddTransformation("AppendA", transformationErrorA)
	_ = rule.AddTransformation("AppendB", transformationErrorB)
	_, error := rule.executeTransformations("arg")
	if len(error) != 2 {
		t.Fatalf("Expected 2 errors executing transformations that returns errors, got %d", len(error))
	}
	if error[0].Error() != "errorA" {
		t.Errorf("Expected errorA in position error[0], got %s", error[0].Error())
	}
	if error[1].Error() != "errorB" {
		t.Errorf("Expected errorB in position error[1], got %s", error[1].Error())
	}
}

func TestExecuteTransformationsMultiMatch(t *testing.T) {
	rule := NewRule()
	_ = rule.AddTransformation("AppendA", transformationAppendA)
	_ = rule.AddTransformation("AppendB", transformationAppendB)
	transformedInput, error := rule.executeTransformationsMultimatch("input")
	if error != nil {
		t.Fatalf("Unexecpted errors executing transformations: %v", error)
	}
	if len(transformedInput) != 3 {
		t.Errorf("Expected 3 transformed inputs from executeTransformationsMultimatch, got %d", len(transformedInput))
	}
	if transformedInput[0] != "input" {
		t.Errorf("Expected input in position transformedInput[0], got %s", transformedInput[0])
	}
	if transformedInput[1] != "inputA" {
		t.Errorf("Expected inputA in position transformedInput[1], got %s", transformedInput[1])
	}
	if transformedInput[2] != "inputAB" {
		t.Errorf("Expected inputAB in position transformedInput[2], got %s", transformedInput[2])
	}
}

func TestExecuteTransformationsMultiMatchReturnsMultipleErrors(t *testing.T) {
	rule := NewRule()
	_ = rule.AddTransformation("A", transformationErrorA)
	_ = rule.AddTransformation("B", transformationErrorB)
	_, error := rule.executeTransformationsMultimatch("arg")
	if len(error) != 2 {
		t.Fatalf("Expected 2 errors executing transformations that returns errors, got %d", len(error))
	}
	if error[0].Error() != "errorA" {
		t.Errorf("Expected errorA in position error[0], got %s", error[0].Error())
	}
	if error[1].Error() != "errorB" {
		t.Errorf("Expected errorB in position error[1], got %s", error[1].Error())
	}
}

func TestTransformArgSimple(t *testing.T) {
	transformationCache := map[transformationKey]*transformationValue{}
	md := &corazarules.MatchData{
		Variable_: variables.RequestURI,
		Key_:      "REQUEST_URI",
		Value_:    "/test",
		Message_:  "TestMessage",
		Data_:     "TestData",
	}
	rule := NewRule()
	_ = rule.AddTransformation("AppendA", transformationAppendA)
	_ = rule.AddTransformation("AppendB", transformationAppendB)
	args, errs := rule.transformArg(md, 0, transformationCache)
	if errs != nil {
		t.Fatalf("Unexpected errors executing transformations: %v", errs)
	}
	if args[0] != "/testAB" {
		t.Errorf("Expected \"/testAB\", got \"%s\"", args[0])
	}
	if len(transformationCache) != 1 {
		t.Errorf("Expected 1 transformations in cache, got %d", len(transformationCache))
	}
	// Repeating the same transformation, expecting still one element in the cache (that means it is a cache hit)
	args, errs = rule.transformArg(md, 0, transformationCache)
	if errs != nil {
		t.Fatalf("Unexpected errors executing transformations: %v", errs)
	}
	if args[0] != "/testAB" {
		t.Errorf("Expected \"/testAB\", got \"%s\"", args[0])
	}
	if len(transformationCache) != 1 {
		t.Errorf("Expected 1 transformations in cache, got %d", len(transformationCache))
	}
}

func TestTransformArgNoCacheForTXVariable(t *testing.T) {
	transformationCache := map[transformationKey]*transformationValue{}
	md := &corazarules.MatchData{
		Variable_: variables.TX,
		Key_:      "Custom_TX_Variable",
		Value_:    "test",
	}
	rule := NewRule()
	_ = rule.AddTransformation("AppendA", transformationAppendA)
	args, errs := rule.transformArg(md, 0, transformationCache)
	if errs != nil {
		t.Fatalf("Unexpected errors executing transformations: %v", errs)
	}
	if args[0] != "testA" {
		t.Errorf("Expected \"testA\", got \"%s\"", args[0])
	}
	if len(transformationCache) != 0 {
		t.Errorf("Expected 0 transformations in cache, got %d. It is not expected to cache TX variable transformations", len(transformationCache))
	}
}
