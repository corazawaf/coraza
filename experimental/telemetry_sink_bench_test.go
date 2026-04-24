// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// countingSink increments counters per method without touching any mutex
// or I/O — upper bound on the cost of a well-written sink that only reads
// event fields.
type countingSink struct {
	tx, match, err, ready int
}

func (s *countingSink) OnEngineReady(plugintypes.EngineReadyEvent) { s.ready++ }
func (s *countingSink) OnTransaction(plugintypes.TransactionEvent) { s.tx++ }
func (s *countingSink) OnRuleMatch(plugintypes.RuleMatchEvent)     { s.match++ }
func (s *countingSink) OnEngineError(plugintypes.EngineEvent)      { s.err++ }

// timedSink also implements RuleTimingSink so the per-rule benchmark can
// exercise the full hot path.
type timedSink struct {
	countingSink
	timings int
}

func (s *timedSink) OnRuleTimed(plugintypes.RuleTimingEvent) { s.timings++ }

func newBenchWAF(b *testing.B, sink plugintypes.TelemetrySink) coraza.WAF {
	b.Helper()
	cfg := coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
		SecRule REQUEST_HEADERS "@rx .*" "id:2,phase:1,pass,nolog"
	`)
	if sink != nil {
		cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)
	}
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		b.Fatal(err)
	}
	return waf
}

func runBenchTransaction(waf coraza.WAF) {
	tx := waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 0, "127.0.0.1", 80)
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	_ = tx.Close()
}

// BenchmarkTelemetry_NoSink measures the baseline: engine runs with a nil
// TelemetrySink. Hot-path cost per event is a single nil-check.
func BenchmarkTelemetry_NoSink(b *testing.B) {
	waf := newBenchWAF(b, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runBenchTransaction(waf)
	}
}

// BenchmarkTelemetry_NoopSink measures the cost with a non-nil sink whose
// methods are empty bodies. Difference vs _NoSink isolates the cost of
// dispatching through the interface and building event structs.
func BenchmarkTelemetry_NoopSink(b *testing.B) {
	waf := newBenchWAF(b, experimental.NoopTelemetrySink())
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runBenchTransaction(waf)
	}
}

// BenchmarkTelemetry_CountingSink exercises a sink that actually reads
// event fields but does no I/O. Upper bound on the cost of a well-written
// in-process metrics sink.
func BenchmarkTelemetry_CountingSink(b *testing.B) {
	waf := newBenchWAF(b, &countingSink{})
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runBenchTransaction(waf)
	}
}

// BenchmarkTelemetry_PerRuleTimingOff measures the off-state overhead of
// per-rule timing when a RuleTimingSink is wired but the flag is false.
// The hot-path cost is a single atomic load plus a cached nil check per
// phase — must stay within noise of the plain counting sink.
func BenchmarkTelemetry_PerRuleTimingOff(b *testing.B) {
	waf := newBenchWAFWithTiming(b, &timedSink{}, false)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runBenchTransaction(waf)
	}
}

// BenchmarkTelemetry_PerRuleTimingOn measures the on-state cost. Each rule
// evaluated pays two time.Now() calls plus one interface dispatch.
func BenchmarkTelemetry_PerRuleTimingOn(b *testing.B) {
	waf := newBenchWAFWithTiming(b, &timedSink{}, true)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runBenchTransaction(waf)
	}
}

func newBenchWAFWithTiming(b *testing.B, sink plugintypes.TelemetrySink, timingOn bool) coraza.WAF {
	b.Helper()
	cfg := coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
		SecRule REQUEST_HEADERS "@rx .*" "id:2,phase:1,pass,nolog"
	`)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)
	cfg = experimental.WAFConfigWithPerRuleTiming(cfg, timingOn)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		b.Fatal(err)
	}
	return waf
}
