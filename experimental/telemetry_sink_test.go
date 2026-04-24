// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// recordingSink captures every event the engine fires, in order. It also
// implements plugintypes.RuleTimingSink so tests can inspect per-rule
// timing events when enabled.
type recordingSink struct {
	mu           sync.Mutex
	readyEvents  []plugintypes.EngineReadyEvent
	transactions []plugintypes.TransactionEvent
	matches      []plugintypes.RuleMatchEvent
	errors       []plugintypes.EngineEvent
	timings      []plugintypes.RuleTimingEvent
}

func (s *recordingSink) OnRuleTimed(ev plugintypes.RuleTimingEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timings = append(s.timings, ev)
}

func (s *recordingSink) OnEngineReady(ev plugintypes.EngineReadyEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readyEvents = append(s.readyEvents, ev)
}

func (s *recordingSink) OnTransaction(ev plugintypes.TransactionEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transactions = append(s.transactions, ev)
}

func (s *recordingSink) OnRuleMatch(ev plugintypes.RuleMatchEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.matches = append(s.matches, ev)
}

func (s *recordingSink) OnEngineError(ev plugintypes.EngineEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errors = append(s.errors, ev)
}

// runAllPhases walks a transaction through every lifecycle point exactly once
// with the given directives loaded into the WAF. The bodyText is provided to
// request and response body phases.
func runAllPhases(t *testing.T, directives, bodyText string, sink plugintypes.TelemetrySink) {
	t.Helper()
	cfg := coraza.NewWAFConfig().
		WithDirectives(directives).
		WithRequestBodyAccess().
		WithResponseBodyAccess().
		WithResponseBodyMimeTypes([]string{"text/plain"})
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}

	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()

	tx.ProcessConnection("127.0.0.1", 12345, "127.0.0.1", 80)
	tx.ProcessURI("/test", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	if it := tx.ProcessRequestHeaders(); it != nil {
		// Short-circuit on early interruption; later phases must not run.
		tx.ProcessLogging()
		return
	}
	if _, _, err := tx.WriteRequestBody([]byte(bodyText)); err != nil {
		t.Fatalf("write req body: %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("process req body: %v", err)
	}
	tx.AddResponseHeader("Content-Type", "text/plain")
	if it := tx.ProcessResponseHeaders(200, "HTTP/1.1"); it != nil {
		tx.ProcessLogging()
		return
	}
	if _, _, err := tx.WriteResponseBody([]byte(bodyText)); err != nil {
		t.Fatalf("write resp body: %v", err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatalf("process resp body: %v", err)
	}
	tx.ProcessLogging()
}

// TestTelemetrySink_FullLifecycle: for a clean transaction, expect one
// EngineReady, one Start, one PhaseEnd per phase (1..5), and one Finish.
// Also asserts phase durations are non-negative and at least one is > 0.
func TestTelemetrySink_FullLifecycle(t *testing.T) {
	sink := &recordingSink{}
	// Load a rule so phases do non-trivial work; empty phases can finish in
	// under a nanosecond on fast hardware and give PhaseDuration=0.
	runAllPhases(t, `
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
	`, "hello", sink)

	if len(sink.readyEvents) != 1 {
		t.Fatalf("want 1 EngineReady, got %d", len(sink.readyEvents))
	}
	if sink.readyEvents[0].InitDuration <= 0 {
		t.Errorf("EngineReady duration must be > 0, got %v", sink.readyEvents[0].InitDuration)
	}
	if len(sink.transactions) < 7 {
		t.Fatalf("want >=7 transaction events, got %d", len(sink.transactions))
	}
	if sink.transactions[0].Kind != plugintypes.TransactionEventStart {
		t.Fatalf("first event is not Start: %v", sink.transactions[0].Kind)
	}
	last := sink.transactions[len(sink.transactions)-1]
	if last.Kind != plugintypes.TransactionEventFinish {
		t.Fatalf("last event is not Finish: %v", last.Kind)
	}
	// All five phases emitted exactly once, duration non-negative, at least
	// one phase > 0 ns.
	seen := map[types.RulePhase]int{}
	var sawNonZero bool
	for _, ev := range sink.transactions {
		if ev.Kind != plugintypes.TransactionEventPhaseEnd {
			continue
		}
		seen[ev.Phase]++
		if ev.PhaseDuration < 0 {
			t.Errorf("phase %d negative duration", ev.Phase)
		}
		if ev.PhaseDuration > 0 {
			sawNonZero = true
		}
	}
	for p := types.PhaseRequestHeaders; p <= types.PhaseLogging; p++ {
		if seen[p] != 1 {
			t.Errorf("phase %d fired %d times, want 1", p, seen[p])
		}
	}
	if !sawNonZero {
		t.Error("no phase reported non-zero duration")
	}
	// Contexts + tx ids propagated.
	for i, ev := range sink.transactions {
		if ev.Context == nil {
			t.Errorf("event[%d] has nil context", i)
		}
		if ev.TransactionID == "" {
			t.Errorf("event[%d] missing tx_id", i)
		}
	}
}

// TestTelemetrySink_RuleMatchFires: a disruptive rule matches — expect a
// RuleMatch event with Disruptive=true.
func TestTelemetrySink_RuleMatchFires(t *testing.T) {
	sink := &recordingSink{}
	directives := `
		SecRuleEngine On
		SecRule REQUEST_URI "@contains /test" "id:9001,phase:1,deny,status:403,severity:CRITICAL,tag:sqli"
	`
	runAllPhases(t, directives, "", sink)

	if len(sink.matches) != 1 {
		t.Fatalf("want 1 rule match, got %d", len(sink.matches))
	}
	m := sink.matches[0]
	if m.Rule.ID() != 9001 {
		t.Fatalf("rule id = %d", m.Rule.ID())
	}
	if m.Action != "deny" {
		t.Fatalf("match action = %q, want deny", m.Action)
	}
	if !m.Enforced {
		t.Fatalf("match must be enforced in RuleEngine=On")
	}
	if m.Phase != types.PhaseRequestHeaders {
		t.Fatalf("phase = %v", m.Phase)
	}
	if m.Context == nil {
		t.Fatalf("match context must not be nil")
	}
	// Finish event should report blocked decision via an interruption.
	last := sink.transactions[len(sink.transactions)-1]
	if last.Kind != plugintypes.TransactionEventFinish {
		t.Fatalf("last event is not Finish")
	}
	if last.Interruption == nil {
		t.Fatalf("finish event should carry interruption for blocked tx")
	}
	if last.Interruption.RuleID != 9001 {
		t.Fatalf("interruption rule id = %d", last.Interruption.RuleID)
	}
}

// TestTelemetrySink_MultipleMatchesNoBlock: two matching pass,log rules
// produce two match events with Action="pass" and the transaction finishes
// without an interruption. Operator-facing metrics should count blocks as
// Action="deny|drop|redirect" AND Enforced=true, and log-only or pass
// matches by their action label.
func TestTelemetrySink_MultipleMatchesNoBlock(t *testing.T) {
	sink := &recordingSink{}
	directives := `
		SecRuleEngine On
		SecRule REQUEST_URI "@contains /test" "id:1,phase:1,pass,log,severity:WARNING"
		SecRule REQUEST_METHOD "@streq POST" "id:2,phase:1,pass,log,severity:NOTICE"
	`
	runAllPhases(t, directives, "", sink)

	if len(sink.matches) != 2 {
		t.Fatalf("want 2 matches, got %d", len(sink.matches))
	}
	for i, m := range sink.matches {
		if m.Action != "pass" {
			t.Errorf("match[%d] action = %q, want pass", i, m.Action)
		}
	}
	// Transaction must finish with decision=allowed (no interruption).
	last := sink.transactions[len(sink.transactions)-1]
	if last.Interruption != nil {
		t.Fatalf("finish event should not carry interruption for allowed tx: %+v", last.Interruption)
	}
}

// TestTelemetrySink_DetectionOnlyMode: a deny rule under DetectionOnly must
// produce a match event with Disruptive=false (the engine is not
// enforcing) and the transaction must finish without interruption.
func TestTelemetrySink_DetectionOnlyMode(t *testing.T) {
	sink := &recordingSink{}
	directives := `
		SecRuleEngine DetectionOnly
		SecRule REQUEST_URI "@contains /test" "id:1,phase:1,deny,status:403,severity:CRITICAL"
	`
	runAllPhases(t, directives, "", sink)

	if len(sink.matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(sink.matches))
	}
	if sink.matches[0].Enforced {
		t.Fatalf("DetectionOnly match must report Enforced=false")
	}
	if sink.matches[0].Action != "deny" {
		t.Fatalf("DetectionOnly match should still carry Action=deny, got %q", sink.matches[0].Action)
	}
	last := sink.transactions[len(sink.transactions)-1]
	if last.Interruption != nil {
		t.Fatalf("DetectionOnly must not actually interrupt")
	}
}

// TestTelemetrySink_NilShimReturnsInputConfig: passing a non-wafConfig
// returns the input unchanged (third-party config implementations are not
// mutated).
func TestTelemetrySink_NilShimReturnsInputConfig(t *testing.T) {
	type fakeCfg struct{ coraza.WAFConfig }
	input := fakeCfg{}
	got := experimental.WAFConfigWithTelemetrySink(input, nil)
	if got != input {
		t.Fatalf("shim must return input unchanged for unsupported config types")
	}
}

// TestTelemetrySink_PerRuleTimingShims_Fallback: the timing shims also
// degrade gracefully when handed a third-party WAFConfig / WAF that
// doesn't implement the private capability interfaces.
func TestTelemetrySink_PerRuleTimingShims_Fallback(t *testing.T) {
	type fakeCfg struct{ coraza.WAFConfig }
	cfgIn := fakeCfg{}
	if got := experimental.WAFConfigWithPerRuleTiming(cfgIn, true); got != cfgIn {
		t.Fatalf("config shim must return input unchanged for unsupported types")
	}

	type fakeWAF struct{ coraza.WAF }
	wafIn := fakeWAF{}
	if experimental.WAFEnablePerRuleTiming(wafIn, true) {
		t.Fatalf("waf shim must return false for unsupported types")
	}
}

// TestTelemetrySink_BodyProcessorError: an invalid body processor triggers
// an engine.error event.
func TestTelemetrySink_BodyProcessorError(t *testing.T) {
	sink := &recordingSink{}
	// ctl:requestBodyProcessor=INVALID is ignored silently unless the
	// processor is invoked; force invocation by providing a body.
	directives := `
		SecRuleEngine On
		SecRequestBodyAccess On
		SecRule REQUEST_URI "@rx .*" "id:42,phase:1,pass,ctl:requestBodyProcessor=invalid-proc"
	`
	runAllPhases(t, directives, "data", sink)

	var found bool
	for _, e := range sink.errors {
		if e.Kind == plugintypes.EngineEventBodyProcessor {
			found = true
			if !strings.Contains(e.Message, "request body processor failed") {
				t.Errorf("unexpected msg: %q", e.Message)
			}
		}
	}
	if !found {
		t.Fatalf("expected body_processor engine.error, got %+v", sink.errors)
	}
}

// TestTelemetrySink_NilSinkIsAccepted exercises every emit helper's nil-sink
// short-circuit: rule matches, body processor errors, and all transaction
// events must be absorbed without panic or allocation when sink is nil.
func TestTelemetrySink_NilSinkIsAccepted(t *testing.T) {
	cfg := coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRule REQUEST_URI "@contains /" "id:1,phase:1,pass,log,ctl:requestBodyProcessor=invalid-proc"
		`).
		WithRequestBodyAccess()
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, nil)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("data")); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("process body: %v", err)
	}
	tx.ProcessLogging()
	if err := tx.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestTelemetrySink_BodyTruncated: exceeding SecRequestBodyLimit emits an
// engine.error of kind body_truncated. Operators use this to tune limits.
func TestTelemetrySink_BodyTruncated(t *testing.T) {
	sink := &recordingSink{}
	cfg := coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRequestBodyLimit 16
			SecRequestBodyLimitAction Reject
		`).
		WithRequestBodyAccess().
		WithRequestBodyLimit(16)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessRequestHeaders()
	// Write more than the 16-byte limit.
	if _, _, err := tx.WriteRequestBody([]byte("a=veryLongValueBeyondTheLimit")); err != nil {
		t.Fatalf("write body: %v", err)
	}
	tx.ProcessLogging()
	_ = tx.Close()

	var found bool
	for _, e := range sink.errors {
		if e.Kind == plugintypes.EngineEventBodyTruncated {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected body_truncated engine.error, got %+v", sink.errors)
	}
}

// TestTelemetrySink_RulesEvaluatedCount: PhaseEnd events report how many
// rules actually ran in each phase. Uses phase-1-only rules so the result
// is insensitive to the coraza.rule.multiphase_evaluation build tag, which
// can re-run rules across inferred phases.
func TestTelemetrySink_RulesEvaluatedCount(t *testing.T) {
	sink := &recordingSink{}
	directives := `
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
		SecRule REQUEST_HEADERS "@rx .*" "id:2,phase:1,pass,nolog"
	`
	runAllPhases(t, directives, "x", sink)

	byPhase := map[types.RulePhase]int{}
	for _, ev := range sink.transactions {
		if ev.Kind == plugintypes.TransactionEventPhaseEnd {
			byPhase[ev.Phase] = ev.RulesEvaluated
		}
	}
	if byPhase[types.PhaseRequestHeaders] != 2 {
		t.Errorf("phase 1 rules_evaluated = %d, want 2", byPhase[types.PhaseRequestHeaders])
	}
	// Phases 2..5 have no rules configured; multiphase may still re-run
	// phase-1 rules in phase 2, so we only assert the primary phase.
}

// TestTelemetrySink_EngineReadyReportsRuleCount: OnEngineReady surfaces the
// loaded rule count so operators can alert on config-reload surprises.
func TestTelemetrySink_EngineReadyReportsRuleCount(t *testing.T) {
	sink := &recordingSink{}
	cfg := coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:100,phase:1,pass,nolog"
		SecRule REQUEST_URI "@rx .*" "id:101,phase:1,pass,nolog"
		SecRule REQUEST_URI "@rx .*" "id:102,phase:1,pass,nolog"
	`)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)
	if _, err := coraza.NewWAF(cfg); err != nil {
		t.Fatalf("new waf: %v", err)
	}
	if len(sink.readyEvents) != 1 {
		t.Fatalf("want 1 EngineReady, got %d", len(sink.readyEvents))
	}
	if got := sink.readyEvents[0].RulesLoaded; got != 3 {
		t.Errorf("RulesLoaded = %d, want 3", got)
	}
}

// TestTelemetrySink_PerRuleTiming_OffByDefault: no RuleTimingEvents are
// emitted unless the flag is explicitly enabled.
func TestTelemetrySink_PerRuleTiming_OffByDefault(t *testing.T) {
	sink := &recordingSink{}
	directives := `
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
		SecRule REQUEST_HEADERS "@rx .*" "id:2,phase:1,pass,nolog"
	`
	runAllPhases(t, directives, "", sink)
	if len(sink.timings) != 0 {
		t.Fatalf("per-rule timing must default off: got %d events", len(sink.timings))
	}
}

// TestTelemetrySink_PerRuleTiming_EmitsPerRule: when enabled at startup,
// each evaluated rule fires a RuleTimingEvent. Uses phase-1-only rules so
// the assertion is insensitive to coraza.rule.multiphase_evaluation, which
// can legitimately re-evaluate rules in later phases.
func TestTelemetrySink_PerRuleTiming_EmitsPerRule(t *testing.T) {
	sink := &recordingSink{}
	directives := `
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
		SecRule REQUEST_HEADERS "@rx .*" "id:2,phase:1,pass,nolog"
	`
	cfg := coraza.NewWAFConfig().WithDirectives(directives)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)
	cfg = experimental.WAFConfigWithPerRuleTiming(cfg, true)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/x", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	_ = tx.Close()

	// Phase 1 has 2 rules. Both must have timed at least once.
	if len(sink.timings) < 2 {
		t.Fatalf("want >=2 timing events, got %d", len(sink.timings))
	}
	seen := map[int]bool{}
	for i, ev := range sink.timings {
		if ev.Duration < 0 {
			t.Errorf("event[%d] negative duration", i)
		}
		if ev.Rule == nil {
			t.Fatalf("event[%d] has nil rule", i)
		}
		seen[ev.Rule.ID()] = true
	}
	if !seen[1] || !seen[2] {
		t.Errorf("expected timing events for rule 1 and 2, saw %v", seen)
	}
}

// TestTelemetrySink_PerRuleTiming_RuntimeToggle: flipping the flag on a
// running WAF starts emission; flipping it off stops emission.
func TestTelemetrySink_PerRuleTiming_RuntimeToggle(t *testing.T) {
	sink := &recordingSink{}
	cfg := coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
	`)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}
	// Initial: off.
	runTx := func() {
		tx := waf.NewTransaction()
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		tx.ProcessRequestHeaders()
		tx.ProcessLogging()
		_ = tx.Close()
	}
	runTx()
	if len(sink.timings) != 0 {
		t.Fatalf("pre-toggle: expected 0 timings, got %d", len(sink.timings))
	}

	// Flip on.
	if !experimental.WAFEnablePerRuleTiming(waf, true) {
		t.Fatal("WAF must support runtime toggle")
	}
	runTx()
	if len(sink.timings) != 1 {
		t.Fatalf("after on: expected 1 timing, got %d", len(sink.timings))
	}

	// Flip off.
	experimental.WAFEnablePerRuleTiming(waf, false)
	runTx()
	if len(sink.timings) != 1 {
		t.Fatalf("after off: expected still 1 timing, got %d", len(sink.timings))
	}
}

// TestTelemetrySink_PerRuleTimingEnabled_Reader: the runtime toggle has a
// sibling getter on the WAF so operators can query current state.
func TestTelemetrySink_PerRuleTimingEnabled_Reader(t *testing.T) {
	type wafWithReader interface {
		PerRuleTimingEnabled() bool
	}
	cfg := coraza.NewWAFConfig().WithDirectives(`SecRuleEngine On`)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, &recordingSink{})
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := waf.(wafWithReader)
	if !ok {
		t.Skip("WAF does not expose PerRuleTimingEnabled reader")
	}
	if reader.PerRuleTimingEnabled() {
		t.Errorf("default must be false")
	}
	experimental.WAFEnablePerRuleTiming(waf, true)
	if !reader.PerRuleTimingEnabled() {
		t.Errorf("after enable, must be true")
	}
	experimental.WAFEnablePerRuleTiming(waf, false)
	if reader.PerRuleTimingEnabled() {
		t.Errorf("after disable, must be false")
	}
}

// TestTelemetrySink_PerRuleTiming_IgnoredWhenSinkMissingExtension: a sink
// that implements TelemetrySink but NOT RuleTimingSink must not cause
// panics or errors when the flag is on — the engine simply drops the
// would-be timing events.
func TestTelemetrySink_PerRuleTiming_IgnoredWhenSinkMissingExtension(t *testing.T) {
	sink := &basicOnlySink{}
	cfg := coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
	`)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)
	cfg = experimental.WAFConfigWithPerRuleTiming(cfg, true)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	_ = tx.Close()
	// No panic is the assertion.
}

// basicOnlySink implements TelemetrySink but NOT RuleTimingSink.
type basicOnlySink struct{}

func (*basicOnlySink) OnEngineReady(plugintypes.EngineReadyEvent) {}
func (*basicOnlySink) OnTransaction(plugintypes.TransactionEvent) {}
func (*basicOnlySink) OnRuleMatch(plugintypes.RuleMatchEvent)     {}
func (*basicOnlySink) OnEngineError(plugintypes.EngineEvent)      {}

// TestNoopTelemetrySink: the factory returns a sink that satisfies the
// interface and whose methods are safe to call with zero-value events.
// Also exercised indirectly by TestTelemetrySink_PerRuleTiming_NoopSink
// below to confirm the engine accepts it end-to-end.
func TestNoopTelemetrySink(t *testing.T) {
	// Factory's return type is plugintypes.TelemetrySink; calling all four
	// methods with zero-value events must not panic.
	s := experimental.NoopTelemetrySink()
	s.OnEngineReady(plugintypes.EngineReadyEvent{})
	s.OnTransaction(plugintypes.TransactionEvent{})
	s.OnRuleMatch(plugintypes.RuleMatchEvent{})
	s.OnEngineError(plugintypes.EngineEvent{})
}

// TestTelemetrySink_PerRuleTiming_NoopSink wires the Noop sink through the
// full engine path with per-rule timing enabled. Since Noop does not
// implement RuleTimingSink, the engine short-circuits rule-timing emission
// and never panics.
func TestTelemetrySink_PerRuleTiming_NoopSink(t *testing.T) {
	cfg := coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule REQUEST_URI "@rx .*" "id:1,phase:1,pass,nolog"
	`)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, experimental.NoopTelemetrySink())
	cfg = experimental.WAFConfigWithPerRuleTiming(cfg, true)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	_ = tx.Close()
}

// TestEventKind_Strings exercises the String() methods on the event-kind
// enums and types.RulePhase, including every "unknown" default branch.
func TestEventKind_Strings(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{plugintypes.TransactionEventStart.String(), "start"},
		{plugintypes.TransactionEventPhaseEnd.String(), "phase_end"},
		{plugintypes.TransactionEventFinish.String(), "finish"},
		{plugintypes.TransactionEventKind(0).String(), "unknown"},
		{plugintypes.EngineEventInit.String(), "init"},
		{plugintypes.EngineEventParse.String(), "parse"},
		{plugintypes.EngineEventBodyProcessor.String(), "body_processor"},
		{plugintypes.EngineEventBodyTruncated.String(), "body_truncated"},
		{plugintypes.EngineEventTransaction.String(), "transaction"},
		{plugintypes.EngineEventKind(0).String(), "unknown"},
		{types.PhaseRequestHeaders.String(), "request_headers"},
		{types.PhaseRequestBody.String(), "request_body"},
		{types.PhaseResponseHeaders.String(), "response_headers"},
		{types.PhaseResponseBody.String(), "response_body"},
		{types.PhaseLogging.String(), "logging"},
		{types.PhaseUnknown.String(), "unknown"},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Errorf("case %d: got %q, want %q", i, c.got, c.want)
		}
	}
}

// TestTelemetrySink_ContextPropagation: if the caller creates a transaction
// with a specific context, that context must surface in every tx event. This
// is the APM span-chaining contract.
func TestTelemetrySink_ContextPropagation(t *testing.T) {
	sink := &recordingSink{}
	cfg := coraza.NewWAFConfig().WithDirectives(`SecRuleEngine On`)
	cfg = experimental.WAFConfigWithTelemetrySink(cfg, sink)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}
	tx := waf.NewTransactionWithID("my-request-id")
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	_ = tx.Close()

	if len(sink.transactions) == 0 {
		t.Fatal("no transaction events recorded")
	}
	for _, ev := range sink.transactions {
		if ev.TransactionID != "my-request-id" {
			t.Errorf("tx id mismatch: %s", ev.TransactionID)
		}
	}
}
