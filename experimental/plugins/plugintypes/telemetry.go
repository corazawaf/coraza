// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

import (
	"context"
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

// TransactionEventKind classifies a TransactionEvent. The engine emits exactly
// one Start event per transaction, one PhaseEnd event per phase actually
// evaluated, and one Finish event when the transaction is closed.
type TransactionEventKind uint8

const (
	// TransactionEventStart is emitted once, after the transaction struct is
	// initialized and before any phase has been evaluated.
	TransactionEventStart TransactionEventKind = iota + 1

	// TransactionEventPhaseEnd is emitted at the end of each evaluated phase.
	// The PhaseDuration field carries the time spent inside that phase.
	TransactionEventPhaseEnd

	// TransactionEventFinish is emitted once, at transaction close. Carries
	// the final interruption (if any) so a sink can classify the outcome.
	TransactionEventFinish
)

// String returns a short, stable identifier for the event kind suitable for
// use as a metric label value or a log key.
func (k TransactionEventKind) String() string {
	switch k {
	case TransactionEventStart:
		return "start"
	case TransactionEventPhaseEnd:
		return "phase_end"
	case TransactionEventFinish:
		return "finish"
	}
	return "unknown"
}

// TransactionEvent is passed to TelemetrySink.OnTransaction.
//
// TransactionEvent is a value type and safe to copy. Fields not relevant to
// the event kind are zero-valued; sinks must branch on Kind.
type TransactionEvent struct {
	// Kind identifies the lifecycle point that produced the event.
	Kind TransactionEventKind

	// TransactionID is the transaction identifier and is always set.
	TransactionID string

	// Context is the transaction's parent context (typically the HTTP request
	// context). Sinks that start OpenTelemetry spans should pass this context
	// to their tracer so spans chain to the parent request trace. Never nil.
	Context context.Context

	// Phase is only meaningful for TransactionEventPhaseEnd and identifies
	// which phase just finished evaluating.
	Phase types.RulePhase

	// PhaseDuration is only meaningful for TransactionEventPhaseEnd and
	// contains the wall-clock time spent inside the phase.
	PhaseDuration time.Duration

	// RulesEvaluated is only meaningful for TransactionEventPhaseEnd and
	// carries how many rules actually executed in that phase (after
	// skips/excludes/allow-type short-circuits). Useful for answering
	// "why did this request spend so long in phase 2?" without enabling
	// per-rule timing.
	RulesEvaluated int

	// Interruption carries the current interruption (if any). For
	// TransactionEventPhaseEnd it reflects whether the phase ended with an
	// interruption. For TransactionEventFinish it is the terminal decision.
	// nil if the transaction has not been interrupted.
	Interruption *types.Interruption
}

// RuleMatchEvent is passed to TelemetrySink.OnRuleMatch. It is emitted
// synchronously after a rule has matched and its metadata has been appended
// to the transaction's matched-rule list.
type RuleMatchEvent struct {
	// TransactionID is the ID of the transaction in which the match occurred.
	TransactionID string

	// Context is the transaction context. Never nil.
	Context context.Context

	// Rule is the metadata of the rule that matched. Never nil.
	Rule types.RuleMetadata

	// Phase is the phase during which the match was evaluated.
	Phase types.RulePhase

	// Action is the disruptive-type action configured on the rule, if any:
	// one of "deny", "drop", "pass", "allow", "redirect", or the empty
	// string when the rule has no disruptive-type action slot (log-only
	// matches, chained sub-rules).
	//
	// Note: "pass" is classified as a disruptive-type action by SecLang
	// semantics even though it does not block. Metrics that count "real"
	// blocks should filter on Action == "deny" || "drop" || "redirect",
	// ideally combined with Enforced == true.
	Action string

	// Enforced is true when the engine actually applied the Action — i.e.
	// the rule engine is On (not DetectionOnly) and the rule had a
	// disruptive-type action. In DetectionOnly mode, Action still carries
	// the intended action but Enforced is false so sinks can distinguish
	// "would-be blocks" from real ones.
	Enforced bool

	// Data carries the matched variables and their values.
	//
	// Security: Data values are attacker-controlled (they are the request
	// bytes that tripped the rule). Sinks MUST NOT use these values as
	// metric labels or span attributes — an attacker can trivially force
	// cardinality explosion on the metrics backend. Log them only after
	// redaction and truncation, or drop them entirely. Values may also
	// contain PII (credit cards, bearer tokens, session data) that a naive
	// log-shipper would leak to downstream systems.
	Data []types.MatchData
}

// EngineEventKind enumerates engine-internal error categories. The set is
// intentionally small so sinks can use Kind as a bounded-cardinality metric
// label.
type EngineEventKind uint8

const (
	// EngineEventInit signals a failure during WAF construction or validation.
	EngineEventInit EngineEventKind = iota + 1

	// EngineEventParse signals a failure while parsing SecLang directives.
	EngineEventParse

	// EngineEventBodyProcessor signals a failure in a configured body
	// processor (URLENCODED, JSON, XML, etc.).
	EngineEventBodyProcessor

	// EngineEventBodyTruncated signals that a request or response body was
	// truncated because it exceeded the configured limit and the engine
	// interrupted the transaction as a result. This is not an unexpected
	// failure but operators need to see it to tune limits.
	EngineEventBodyTruncated

	// EngineEventTransaction signals a generic transaction-time error.
	EngineEventTransaction
)

// String returns a short, stable identifier for the kind suitable for use
// as a metric label value or a log key.
func (k EngineEventKind) String() string {
	switch k {
	case EngineEventInit:
		return "init"
	case EngineEventParse:
		return "parse"
	case EngineEventBodyProcessor:
		return "body_processor"
	case EngineEventBodyTruncated:
		return "body_truncated"
	case EngineEventTransaction:
		return "transaction"
	}
	return "unknown"
}

// EngineEvent is passed to TelemetrySink.OnEngineError. It is emitted for
// engine-internal failures that are not themselves rule matches.
type EngineEvent struct {
	// Kind identifies the failure category.
	Kind EngineEventKind

	// TransactionID is set when the failure is transaction-scoped and empty
	// for init- or parse-time failures that have no transaction.
	TransactionID string

	// Phase is the rule phase in which the failure occurred. Zero when the
	// failure is not phase-scoped.
	Phase types.RulePhase

	// Err is the underlying error. May be nil when only Message is set.
	Err error

	// Message is a short human-readable description of the failure. May be
	// empty when only Err is set.
	Message string
}

// RuleTimingEvent is emitted for every evaluated rule when per-rule timing
// is enabled on the WAF. This is a HIGH-FREQUENCY, HIGH-CARDINALITY signal
// — expect hundreds of events per transaction and bounded only by the
// loaded ruleset size (~450 for CRS paranoia 2). Opt in only when
// investigating a specific performance issue.
type RuleTimingEvent struct {
	// TransactionID is the ID of the transaction in which the rule ran.
	TransactionID string

	// Rule is the metadata of the rule that was evaluated.
	Rule types.RuleMetadata

	// Phase is the phase in which the rule ran.
	Phase types.RulePhase

	// Duration is the wall-clock time the rule evaluation took, including
	// variable resolution, transformations, operator execution, and any
	// disruptive action evaluation.
	Duration time.Duration

	// Matched is true when the rule's evaluation produced at least one
	// match record on this invocation.
	Matched bool
}

// RuleTimingSink is an optional extension interface. TelemetrySinks that
// want per-rule timing events should implement it in addition to
// TelemetrySink. The engine type-asserts once at NewWAF time and caches
// the result, so unimplemented sinks pay no runtime cost.
//
// Implementations MUST follow the same non-blocking / concurrent-safe /
// no-panic contract as TelemetrySink.
type RuleTimingSink interface {
	OnRuleTimed(ev RuleTimingEvent)
}

// EngineReadyEvent is passed to TelemetrySink.OnEngineReady once per WAF
// instance, after all directives have been parsed and the WAF has validated.
// Sinks use it to emit process-scope "info" metrics: what is this node
// running and how long did it take to boot.
type EngineReadyEvent struct {
	// RulesLoaded is the number of compiled SecLang rules loaded into the
	// WAF. Useful for alerting on config-reload surprises
	// ("we lost 40 rules after that deploy").
	RulesLoaded int

	// InitDuration is the wall-clock time spent inside coraza.NewWAF —
	// parsing directives, compiling regex, resolving rule chains. Critical
	// for serverless/edge cold-start budgets.
	InitDuration time.Duration
}

// TelemetrySink receives engine telemetry events.
//
// The engine invokes sink methods synchronously on the request-evaluation hot
// path. Implementations MUST therefore:
//
//   - return quickly (buffer to a channel or similar if heavy work is needed);
//   - be safe for concurrent invocation from multiple transactions;
//   - never panic.
//
// All methods receive events by value. Implementations must not retain
// pointers to Err or Interruption beyond the duration of the call: the engine
// may pool and reuse transaction objects once the event returns.
//
// The engine treats a nil TelemetrySink as "no telemetry" and short-circuits
// all event emission without allocation.
//
// A minimal implementation is six lines — use it as a starting point before
// wiring events into Prometheus, OpenTelemetry, or your host's native
// telemetry stack:
//
//	type printSink struct{}
//	func (printSink) OnEngineReady(ev plugintypes.EngineReadyEvent)  {}
//	func (printSink) OnTransaction(ev plugintypes.TransactionEvent)  { fmt.Printf("%+v\n", ev) }
//	func (printSink) OnRuleMatch(ev plugintypes.RuleMatchEvent)       { fmt.Printf("%+v\n", ev) }
//	func (printSink) OnEngineError(ev plugintypes.EngineEvent)        { fmt.Printf("%+v\n", ev) }
//
// This interface is experimental and may change before Coraza v4.
type TelemetrySink interface {
	// OnEngineReady is invoked exactly once per WAF instance, after all
	// directives have been parsed and validation has succeeded.
	OnEngineReady(ev EngineReadyEvent)

	// OnTransaction is invoked at transaction start, at the end of each
	// evaluated phase, and at transaction close.
	OnTransaction(ev TransactionEvent)

	// OnRuleMatch is invoked once per rule match, synchronously, after the
	// rule's match record has been appended to the transaction.
	OnRuleMatch(ev RuleMatchEvent)

	// OnEngineError is invoked for engine-internal failures that are not rule
	// matches (body processor errors, body truncation, etc.).
	OnEngineError(ev EngineEvent)
}
