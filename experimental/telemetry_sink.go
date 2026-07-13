// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// wafConfigWithTelemetrySink is the private capability interface implemented
// by the package-internal wafConfig. Keeping the method off the public
// WAFConfig interface lets us iterate on the telemetry contract before v4
// without breaking embedders.
type wafConfigWithTelemetrySink interface {
	WithTelemetrySink(plugintypes.TelemetrySink) coraza.WAFConfig
}

// WAFConfigWithTelemetrySink attaches a TelemetrySink to the provided
// WAFConfig. A nil sink disables telemetry emission without allocation on
// the hot path.
//
// The returned WAFConfig is a new value; the input is not mutated. If the
// provided WAFConfig does not support telemetry (e.g. a third-party
// implementation), the input is returned unchanged.
//
// This API is experimental and may change before Coraza v4.
func WAFConfigWithTelemetrySink(
	cfg coraza.WAFConfig,
	sink plugintypes.TelemetrySink,
) coraza.WAFConfig {
	if c, ok := cfg.(wafConfigWithTelemetrySink); ok {
		return c.WithTelemetrySink(sink)
	}
	return cfg
}

// wafConfigWithPerRuleTiming is the private capability interface for
// enabling per-rule timing at startup.
type wafConfigWithPerRuleTiming interface {
	WithPerRuleTiming(bool) coraza.WAFConfig
}

// WAFConfigWithPerRuleTiming turns on per-rule timing at startup.
//
// Per-rule timing is HIGH-CARDINALITY (one event per rule per request,
// ~450 for CRS) and HIGH-FREQUENCY. It is meant for investigating a
// specific slow rule, not for continuous observability. Leave it off
// unless you are actively debugging — the off-state cost is a single
// atomic load per phase; the on-state cost is roughly +4–10µs per
// transaction at typical rulesets.
//
// For a running WAF, prefer WAFEnablePerRuleTiming to flip the flag
// without a rebuild.
//
// This API is experimental and may change before Coraza v4.
func WAFConfigWithPerRuleTiming(cfg coraza.WAFConfig, enabled bool) coraza.WAFConfig {
	if c, ok := cfg.(wafConfigWithPerRuleTiming); ok {
		return c.WithPerRuleTiming(enabled)
	}
	return cfg
}

// wafWithPerRuleTimingToggle is the private capability interface for
// flipping per-rule timing on a live WAF.
type wafWithPerRuleTimingToggle interface {
	SetPerRuleTimingEnabled(bool)
}

// WAFEnablePerRuleTiming toggles per-rule timing on a running WAF. Returns
// true when the operation was honoured, false when the WAF implementation
// does not support runtime telemetry toggles (e.g. a third-party WAF).
//
// Safe to call concurrently with active transactions; the change is
// observed on the next rule-evaluation loop.
//
// Typical usage: flip on when investigating a p99 spike, flip off when
// done. Leaving it on continuously is not recommended.
//
// This API is experimental and may change before Coraza v4.
func WAFEnablePerRuleTiming(waf coraza.WAF, enabled bool) bool {
	if w, ok := waf.(wafWithPerRuleTimingToggle); ok {
		w.SetPerRuleTimingEnabled(enabled)
		return true
	}
	return false
}

// NoopTelemetrySink returns a plugintypes.TelemetrySink that discards every
// event.
//
// The engine already treats a nil sink as "no telemetry" for free, so this
// factory exists only for callers that prefer an explicit non-nil sink —
// typically tests or configuration-plumbing code where a nil assignment is
// ambiguous. In production, pass nil.
func NoopTelemetrySink() plugintypes.TelemetrySink {
	return noopSink{}
}

type noopSink struct{}

// Bodies contain a single statement so the coverage tool counts them when
// invoked; an empty body is reported as 0/0 which some dashboards treat as
// uncovered.
func (noopSink) OnEngineReady(ev plugintypes.EngineReadyEvent) { _ = ev }
func (noopSink) OnTransaction(ev plugintypes.TransactionEvent) { _ = ev }
func (noopSink) OnRuleMatch(ev plugintypes.RuleMatchEvent)     { _ = ev }
func (noopSink) OnEngineError(ev plugintypes.EngineEvent)      { _ = ev }
