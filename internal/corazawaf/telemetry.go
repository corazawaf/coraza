// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// The helpers in this file centralize telemetry emission. They all return
// immediately when no sink is configured, so the hot path pays only a nil
// pointer comparison per event.

// SetTelemetrySink attaches a sink to the WAF and caches the optional
// RuleTimingSink interface assertion so the hot path doesn't pay for it
// on every rule evaluation.
//
// Thread-safety: this method is NOT safe to call concurrently with active
// transactions. It writes two plain fields (TelemetrySink and
// ruleTimingSink) that the hot path reads without synchronization; a
// runtime swap would be a data race. Callers must invoke SetTelemetrySink
// before the WAF is handed to any transaction — which is exactly how
// coraza.NewWAF wires it. Use the runtime-togglable
// SetPerRuleTimingEnabled if you need to change behaviour on a live WAF.
func (w *WAF) SetTelemetrySink(sink plugintypes.TelemetrySink) {
	w.TelemetrySink = sink
	if rt, ok := sink.(plugintypes.RuleTimingSink); ok {
		w.ruleTimingSink = rt
	} else {
		w.ruleTimingSink = nil
	}
}

// SetPerRuleTimingEnabled toggles per-rule timing emission at runtime.
// Safe to call concurrently with transaction evaluation; the change is
// observed on the next rule-loop iteration.
func (w *WAF) SetPerRuleTimingEnabled(enabled bool) {
	w.perRuleTimingEnabled.Store(enabled)
}

// PerRuleTimingEnabled reports whether per-rule timing is currently active.
func (w *WAF) PerRuleTimingEnabled() bool {
	return w.perRuleTimingEnabled.Load()
}

// emitRuleTimed fires a RuleTimingEvent. Callers (rulegroup.Eval) must have
// verified that emission should occur by checking the cached
// tx.WAF.ruleTimingSink pointer against nil — this helper trusts them and
// skips the redundant nil check.
func (tx *Transaction) emitRuleTimed(r *Rule, duration time.Duration, matched bool) {
	tx.WAF.ruleTimingSink.OnRuleTimed(plugintypes.RuleTimingEvent{
		TransactionID: tx.id,
		Rule:          &r.RuleMetadata,
		Phase:         tx.lastPhase,
		Duration:      duration,
		Matched:       matched,
	})
}

// emitTransactionStart emits a TransactionEventStart event for the receiver.
func (tx *Transaction) emitTransactionStart() {
	sink := tx.WAF.TelemetrySink
	if sink == nil {
		return
	}
	sink.OnTransaction(plugintypes.TransactionEvent{
		Kind:          plugintypes.TransactionEventStart,
		TransactionID: tx.id,
		Context:       tx.context,
	})
}

// emitPhaseEnd emits a TransactionEventPhaseEnd event carrying the duration
// spent in the phase, the number of rules that actually ran, and the
// current interruption (if any).
func (tx *Transaction) emitPhaseEnd(phase types.RulePhase, duration time.Duration, rulesEvaluated int) {
	sink := tx.WAF.TelemetrySink
	if sink == nil {
		return
	}
	sink.OnTransaction(plugintypes.TransactionEvent{
		Kind:           plugintypes.TransactionEventPhaseEnd,
		TransactionID:  tx.id,
		Context:        tx.context,
		Phase:          phase,
		PhaseDuration:  duration,
		RulesEvaluated: rulesEvaluated,
		Interruption:   tx.interruption,
	})
}

// emitTransactionFinish emits a TransactionEventFinish event. It is called
// from Transaction.Close before the transaction is returned to the pool.
func (tx *Transaction) emitTransactionFinish() {
	sink := tx.WAF.TelemetrySink
	if sink == nil {
		return
	}
	sink.OnTransaction(plugintypes.TransactionEvent{
		Kind:          plugintypes.TransactionEventFinish,
		TransactionID: tx.id,
		Context:       tx.context,
		Interruption:  tx.interruption,
	})
}

// emitRuleMatch emits a RuleMatchEvent synchronously after a rule match has
// been recorded. The event carries the rule metadata, the configured
// disruptive action name (if any), whether it was enforced, and the
// matched-data slice. Sinks that log matched data are responsible for
// redaction and truncation.
func (tx *Transaction) emitRuleMatch(r *Rule, action string, enforced bool, mds []types.MatchData) {
	sink := tx.WAF.TelemetrySink
	if sink == nil {
		return
	}
	sink.OnRuleMatch(plugintypes.RuleMatchEvent{
		TransactionID: tx.id,
		Context:       tx.context,
		Rule:          &r.RuleMetadata,
		Phase:         tx.lastPhase,
		Action:        action,
		Enforced:      enforced,
		Data:          mds,
	})
}

// emitEngineError emits an EngineEvent for transaction-scoped engine
// failures. It is a transaction-bound helper so the transaction context is
// always set.
func (tx *Transaction) emitEngineError(kind plugintypes.EngineEventKind, err error, msg string) {
	sink := tx.WAF.TelemetrySink
	if sink == nil {
		return
	}
	sink.OnEngineError(plugintypes.EngineEvent{
		Kind:          kind,
		TransactionID: tx.id,
		Phase:         tx.lastPhase,
		Err:           err,
		Message:       msg,
	})
}
