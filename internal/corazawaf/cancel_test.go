// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// funcAction runs fn every time the rule it is attached to matches.
type funcAction struct{ fn func() }

func (*funcAction) Init(_ plugintypes.RuleMetadata, _ string) error { return nil }

func (a *funcAction) Evaluate(_ plugintypes.RuleMetadata, _ plugintypes.TransactionState) { a.fn() }

func (*funcAction) Type() plugintypes.ActionType { return plugintypes.ActionTypeNondisruptive }

// addActionRule adds to waf a rule without an operator, which always matches,
// that runs fn in phase.
func addActionRule(t *testing.T, waf *WAF, id int, phase types.RulePhase, fn func()) {
	t.Helper()
	r := NewRule()
	r.ID_ = id
	r.LogID_ = strconv.Itoa(id)
	r.Phase_ = phase
	r.operator = nil
	if err := r.AddAction("test", &funcAction{fn: fn}); err != nil {
		t.Fatal(err)
	}
	if err := waf.Rules.Add(r); err != nil {
		t.Fatal(err)
	}
}

func TestEvalStopsBeforeNextRuleOnceContextIsDone(t *testing.T) {
	waf := NewWAF()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ran []int
	addActionRule(t, waf, 1, types.PhaseRequestBody, func() { ran = append(ran, 1); cancel() })
	addActionRule(t, waf, 2, types.PhaseRequestBody, func() { ran = append(ran, 2) })
	addActionRule(t, waf, 3, types.PhaseRequestBody, func() { ran = append(ran, 3) })

	tx := waf.NewTransactionWithOptions(Options{Context: ctx})
	defer func() { _ = tx.Close() }()
	tx.ProcessRequestHeaders()
	it, err := tx.ProcessRequestBody()
	if !errors.Is(err, ErrPhaseCanceled) {
		t.Errorf("expected an error wrapping ErrPhaseCanceled, got %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected an error wrapping the context's error, got %v", err)
	}
	if it != nil {
		t.Errorf("a phase cut short must not invent an interruption, got %v", it)
	}
	if len(ran) != 1 || ran[0] != 1 {
		t.Errorf("expected only rule 1 to run before the context ended, got %v", ran)
	}
}

func TestRequestHeadersPhaseCutShortIsReportedByRequestBody(t *testing.T) {
	waf := NewWAF()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ran []int
	addActionRule(t, waf, 1, types.PhaseRequestHeaders, func() { ran = append(ran, 1); cancel() })
	addActionRule(t, waf, 2, types.PhaseRequestHeaders, func() { ran = append(ran, 2) })
	addActionRule(t, waf, 3, types.PhaseRequestBody, func() { ran = append(ran, 3) })

	tx := waf.NewTransactionWithOptions(Options{Context: ctx})
	defer func() { _ = tx.Close() }()
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Errorf("a phase cut short must not invent an interruption, got %v", it)
	}
	if _, err := tx.ProcessRequestBody(); !errors.Is(err, ErrPhaseCanceled) {
		t.Errorf("expected ProcessRequestBody to report the cancellation, got %v", err)
	}
	if len(ran) != 1 || ran[0] != 1 {
		t.Errorf("expected only rule 1 to run before the context ended, got %v", ran)
	}
}

func TestLoggingPhaseRunsEveryRuleAfterContextIsDone(t *testing.T) {
	waf := NewWAF()
	ctx, cancel := context.WithCancel(context.Background())
	ran := 0
	addActionRule(t, waf, 1, types.PhaseLogging, func() { ran++ })
	addActionRule(t, waf, 2, types.PhaseLogging, func() { ran++ })

	tx := waf.NewTransactionWithOptions(Options{Context: ctx})
	defer func() { _ = tx.Close() }()
	cancel()
	tx.ProcessLogging()
	if ran != 2 {
		t.Errorf("expected the logging phase to evaluate both rules after the context ended, got %d", ran)
	}
}

// checkAllRulesRun evaluates both request phases of tx, which must have a live
// context, and expects every rule to run and no error.
func checkAllRulesRun(t *testing.T, waf *WAF, tx *Transaction) {
	t.Helper()
	ran := 0
	addActionRule(t, waf, 1, types.PhaseRequestHeaders, func() { ran++ })
	addActionRule(t, waf, 2, types.PhaseRequestBody, func() { ran++ })
	addActionRule(t, waf, 3, types.PhaseRequestBody, func() { ran++ })

	defer func() { _ = tx.Close() }()
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Errorf("unexpected error with a live context: %v", err)
	}
	if ran != 3 {
		t.Errorf("expected every rule to run, got %d", ran)
	}
}

func TestEvalRunsEveryRuleWithLiveContext(t *testing.T) {
	t.Run("default context", func(t *testing.T) {
		waf := NewWAF()
		checkAllRulesRun(t, waf, waf.NewTransaction())
	})
	t.Run("cancelable context", func(t *testing.T) {
		waf := NewWAF()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		checkAllRulesRun(t, waf, waf.NewTransactionWithOptions(Options{Context: ctx}))
	})
}

func TestProcessRequestBodySkipsParsingOnceContextIsDone(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyAccess = true
	ran := 0
	addActionRule(t, waf, 1, types.PhaseRequestBody, func() { ran++ })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tx := waf.NewTransactionWithOptions(Options{Context: ctx})
	defer func() { _ = tx.Close() }()
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("a=b")); err != nil {
		t.Fatal(err)
	}
	cancel()

	if _, err := tx.ProcessRequestBody(); !errors.Is(err, ErrPhaseCanceled) {
		t.Fatalf("expected an error wrapping ErrPhaseCanceled, got %v", err)
	}
	if got := tx.Variables().ArgsPost().Get("a"); len(got) != 0 {
		t.Errorf("the body was parsed after the context ended: %v", got)
	}
	if ran != 0 {
		t.Errorf("expected no rule to run once the context ended, got %d", ran)
	}
}

func TestPhaseContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tx := NewWAF().NewTransactionWithOptions(Options{Context: ctx})
	defer func() { _ = tx.Close() }()

	for phase, bounded := range map[types.RulePhase]bool{
		types.PhaseRequestHeaders:  true,
		types.PhaseRequestBody:     true,
		types.PhaseResponseHeaders: false,
		types.PhaseResponseBody:    false,
		types.PhaseLogging:         false,
	} {
		tx.lastPhase = phase
		if got := tx.PhaseContext().Err() != nil; got != bounded {
			t.Errorf("phase %d: expected the context to be bounded by the transaction's: %t, got %t", phase, bounded, got)
		}
	}
}
