// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/operators"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// mockRecord implements plugintypes.Record for testing.
type mockRecord struct {
	fields    map[string]string
	rawRecord []byte
}

func (r mockRecord) Fields() map[string]string { return r.fields }
func (r mockRecord) Raw() []byte               { return r.rawRecord }

// mockStreamingBodyProcessor implements StreamingBodyProcessor for testing.
type mockStreamingBodyProcessor struct {
	records []mockRecord
	err     error // error to return after all records
}

func (m *mockStreamingBodyProcessor) ProcessRequest(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (m *mockStreamingBodyProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (m *mockStreamingBodyProcessor) ProcessRequestRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	for i, rec := range m.records {
		if err := fn(i, rec); err != nil {
			return err
		}
	}
	return m.err
}

func (m *mockStreamingBodyProcessor) ProcessResponseRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	for i, rec := range m.records {
		if err := fn(i, rec); err != nil {
			return err
		}
	}
	return m.err
}

// dummyStreamDenyAction is a disruptive action for testing streaming evaluation.
type dummyStreamDenyAction struct{}

func (*dummyStreamDenyAction) Init(_ plugintypes.RuleMetadata, _ string) error { return nil }
func (*dummyStreamDenyAction) Evaluate(r plugintypes.RuleMetadata, tx plugintypes.TransactionState) {
	rid := r.ID()
	if rid == noID {
		rid = r.ParentID()
	}
	tx.Interrupt(&types.Interruption{
		Status: r.Status(),
		RuleID: rid,
		Action: "deny",
	})
}
func (*dummyStreamDenyAction) Type() plugintypes.ActionType {
	return plugintypes.ActionTypeDisruptive
}

// newStreamingTestRule creates a rule that matches a given field value.
func newStreamingTestRule(t *testing.T, id int, targetVar variables.RuleVariable, pattern string, deny bool) *Rule {
	t.Helper()
	rule := NewRule()
	rule.ID_ = id
	rule.LogID_ = "test"
	rule.Phase_ = types.PhaseRequestBody
	if targetVar == variables.ResponseArgs {
		rule.Phase_ = types.PhaseResponseBody
	}

	op, err := operators.Get("rx", plugintypes.OperatorOptions{
		Arguments: pattern,
	})
	if err != nil {
		t.Fatal(err)
	}
	rule.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@rx",
		Data:     pattern,
		Negation: false,
	}
	rule.variables = append(rule.variables, ruleVariableParams{
		Variable: targetVar,
	})
	if deny {
		if err := rule.AddAction("deny", &dummyStreamDenyAction{}); err != nil {
			t.Fatalf("add deny action: %v", err)
		}
	}
	rule.Log = true
	rule.Audit = true
	return rule
}

// countingStreamProcessor wraps mockStreamingBodyProcessor and counts processed records.
type countingStreamProcessor struct {
	records []mockRecord
	count   *int
}

func (c *countingStreamProcessor) ProcessRequest(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (c *countingStreamProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (c *countingStreamProcessor) ProcessRequestRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	for i, rec := range c.records {
		*c.count++
		if err := fn(i, rec); err != nil {
			return err
		}
	}
	return nil
}

func (c *countingStreamProcessor) ProcessResponseRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	for i, rec := range c.records {
		*c.count++
		if err := fn(i, rec); err != nil {
			return err
		}
	}
	return nil
}

// sentinelWrappingProcessor simulates a poorly-written processor that wraps
// errStreamInterrupted instead of propagating it cleanly, producing the edge
// case where tx.interruption is set AND a non-sentinel error is returned.
type sentinelWrappingProcessor struct {
	records []mockRecord
}

func (s *sentinelWrappingProcessor) ProcessRequest(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (s *sentinelWrappingProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (s *sentinelWrappingProcessor) ProcessRequestRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	for i, rec := range s.records {
		if err := fn(i, rec); err != nil {
			return fmt.Errorf("processor wrapped: %w", err)
		}
	}
	return nil
}

func (s *sentinelWrappingProcessor) ProcessResponseRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	for i, rec := range s.records {
		if err := fn(i, rec); err != nil {
			return fmt.Errorf("processor wrapped: %w", err)
		}
	}
	return nil
}

func TestProcessRequestBodyStreamingCleanRecords(t *testing.T) {
	waf := NewWAF()
	rule := newStreamingTestRule(t, 100, variables.ArgsPost, "malicious", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.name": "alice"}, rawRecord: []byte(`{"name":"alice"}` + "\n")},
			{fields: map[string]string{"json.1.name": "bob"}, rawRecord: []byte(`{"name":"bob"}` + "\n")},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	it, err := tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatalf("unexpected interruption for clean records")
	}
}

func TestProcessRequestBodyStreamingInterruptionStopsProcessing(t *testing.T) {
	waf := NewWAF()
	rule := newStreamingTestRule(t, 100, variables.ArgsPost, "malicious", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	var processedRecords int
	sp := &countingStreamProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.name": "safe"}, rawRecord: []byte(`{"name":"safe"}` + "\n")},
			{fields: map[string]string{"json.1.name": "malicious-payload"}, rawRecord: []byte(`{"name":"malicious-payload"}` + "\n")},
			{fields: map[string]string{"json.2.name": "should-not-reach"}, rawRecord: []byte(`{"name":"should-not-reach"}` + "\n")},
		},
		count: &processedRecords,
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	it, err := tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it == nil {
		t.Fatal("expected interruption for malicious record")
	}
	if processedRecords != 2 {
		t.Fatalf("expected 2 records processed before interruption, got %d", processedRecords)
	}
}

func TestProcessResponseBodyStreamingInterruption(t *testing.T) {
	waf := NewWAF()
	rule := newStreamingTestRule(t, 400, variables.ResponseArgs, "malicious", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.name": "safe"}, rawRecord: []byte(`{"name":"safe"}` + "\n")},
			{fields: map[string]string{"json.1.name": "malicious-data"}, rawRecord: []byte(`{"name":"malicious-data"}` + "\n")},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ResponseBodyAccess = true

	it, err := tx.processResponseBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it == nil {
		t.Fatal("expected interruption for malicious response record")
	}
}

func TestProcessRequestBodyStreamingTxVariablesPersist(t *testing.T) {
	// TX variables (matchedRules, user-set TX vars) should persist across records
	// for cross-record correlation. ArgsPost is reset per record, but TX-scoped
	// state accumulates.
	waf := NewWAF()

	rule := newStreamingTestRule(t, 200, variables.ArgsPost, "suspicious", false)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.data": "suspicious-1"}, rawRecord: []byte(`{"data":"suspicious-1"}` + "\n")},
			{fields: map[string]string{"json.1.data": "clean"}, rawRecord: []byte(`{"data":"clean"}` + "\n")},
			{fields: map[string]string{"json.2.data": "suspicious-2"}, rawRecord: []byte(`{"data":"suspicious-2"}` + "\n")},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true
	tx.variables.tx.SetIndex("marker", 0, "persist-me")

	it, err := tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatalf("unexpected interruption: %v", it)
	}
	if len(tx.matchedRules) != 2 {
		t.Fatalf("expected 2 matched rules, got %d", len(tx.matchedRules))
	}
	if vals := tx.variables.tx.Get("marker"); len(vals) == 0 || vals[0] != "persist-me" {
		t.Fatalf("TX variable 'marker' did not persist across records, got: %v", vals)
	}
}

func TestProcessRequestBodyStreamingArgsPostIsolated(t *testing.T) {
	// Verify that record 0's fields don't leak into record 1's evaluation.
	// The rule uses deny=false so processing continues through both records.
	waf := NewWAF()
	rule := newStreamingTestRule(t, 300, variables.ArgsPost, "record0-only", false)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.data": "record0-only-value"}, rawRecord: []byte(`{"data":"record0-only-value"}` + "\n")},
			{fields: map[string]string{"json.1.data": "clean"}, rawRecord: []byte(`{"data":"clean"}` + "\n")},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	it, err := tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatal("unexpected interruption")
	}
	// Only record 0 should have matched — if ArgsPost leaked, record 1 would also match
	if len(tx.matchedRules) != 1 {
		t.Fatalf("expected 1 matched rule (record 0 only), got %d — ArgsPost may have leaked between records", len(tx.matchedRules))
	}
}

// TestProcessBodyStreamingProcessorErrorClearsVars verifies that per-record
// variables are cleared after a mid-stream processor error so no stale data
// leaks into subsequent phases.
func TestProcessBodyStreamingProcessorErrorClearsVars(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request bool
	}{
		{"request/argsPost", true},
		{"response/responseArgs", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waf := NewWAF()
			sp := &mockStreamingBodyProcessor{
				records: []mockRecord{
					{fields: map[string]string{"json.0.field": "stale-value"}, rawRecord: []byte("rec\n")},
				},
				err: errors.New("mid-stream processor error"),
			}
			tx := waf.NewTransaction()
			defer tx.Close()

			if tc.request {
				tx.RequestBodyAccess = true
				if _, err := tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{}); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := tx.variables.argsPost.Len(); got != 0 {
					t.Fatalf("argsPost not cleared after processor error, got %d entries", got)
				}
			} else {
				tx.ResponseBodyAccess = true
				if _, err := tx.processResponseBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{}); err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got := tx.variables.responseArgs.Len(); got != 0 {
					t.Fatalf("responseArgs not cleared after processor error, got %d entries", got)
				}
			}
		})
	}
}

// TestProcessRequestBodyStreamingProcessorErrorFallbackEvalNoStaleData verifies that
// argsPost is cleared even when the processor wraps errStreamInterrupted (edge case:
// tx.interruption is set AND a non-sentinel error is returned simultaneously).
func TestProcessRequestBodyStreamingProcessorErrorFallbackEvalNoStaleData(t *testing.T) {
	waf := NewWAF()
	rule := newStreamingTestRule(t, 501, variables.ArgsPost, "stale-value", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &sentinelWrappingProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.field": "stale-value"}, rawRecord: []byte("rec\n")},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	it, err := tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it == nil {
		t.Fatal("expected interruption from per-record eval")
	}
	if got := tx.variables.argsPost.Len(); got != 0 {
		t.Fatalf("argsPost not cleared: has %d entries after wrapped-sentinel error", got)
	}
}

// TestProcessBodyStreamingProcessorErrorFallbackEvalClean verifies that the
// fallback phase evaluation after a processor error runs on empty per-record
// variables, not stale data from the last processed record.
func TestProcessBodyStreamingProcessorErrorFallbackEvalClean(t *testing.T) {
	for _, tc := range []struct {
		name      string
		request   bool
		targetVar variables.RuleVariable
		phase     types.RulePhase
		pattern   string
	}{
		{"request", true, variables.ArgsPost, types.PhaseRequestBody, "clean-field"},
		{"response", false, variables.ResponseArgs, types.PhaseResponseBody, "resp-stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waf := NewWAF()
			rule := newStreamingTestRule(t, 502, tc.targetVar, tc.pattern, true)
			if err := waf.Rules.Add(rule); err != nil {
				t.Fatal(err)
			}

			// Sanity check: the rule fires when the variable contains the pattern.
			txSanity := waf.NewTransaction()
			defer txSanity.Close()
			if tc.request {
				txSanity.variables.argsPost.SetIndex("sanity", 0, tc.pattern)
			} else {
				txSanity.variables.responseArgs.SetIndex("sanity", 0, tc.pattern)
			}
			txSanity.WAF.Rules.Eval(tc.phase, txSanity)
			if txSanity.interruption == nil {
				t.Fatal("sanity check: rule must fire when variable contains pattern")
			}

			sp := &mockStreamingBodyProcessor{
				records: []mockRecord{
					{fields: map[string]string{"json.0.field": "no-match"}, rawRecord: []byte("rec\n")},
				},
				err: errors.New("processor error after safe record"),
			}

			tx := waf.NewTransaction()
			defer tx.Close()

			var it *types.Interruption
			var procErr error
			if tc.request {
				tx.RequestBodyAccess = true
				it, procErr = tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
			} else {
				tx.ResponseBodyAccess = true
				it, procErr = tx.processResponseBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
			}
			if procErr != nil {
				t.Fatalf("unexpected error: %v", procErr)
			}
			if it != nil {
				t.Fatalf("unexpected interruption from fallback eval on stale data: %v", it)
			}

			if tc.request {
				if got := tx.variables.argsPost.Len(); got != 0 {
					t.Fatalf("argsPost not cleared after processor error: %d entries remain", got)
				}
			} else {
				if got := tx.variables.responseArgs.Len(); got != 0 {
					t.Fatalf("responseArgs not cleared after processor error: %d entries remain", got)
				}
			}
		})
	}
}

func TestStreamingTransactionInterface(t *testing.T) {
	// Verify that *Transaction satisfies the StreamingTransaction contract by
	// exercising the exported methods. The compile-time assertion against the
	// exported experimental.StreamingTransaction interface is in
	// streaming_interface_test.go (package corazawaf_test) to avoid the circular
	// import that would result from importing experimental here.
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()

	// Exercise the request path: no body processor set, should pass through
	tx.RequestBodyAccess = true
	tx.ProcessURI("/test", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddRequestHeader("Content-Type", "text/plain")
	tx.ProcessRequestHeaders()

	var reqOut bytes.Buffer
	it, err := tx.ProcessRequestBodyFromStream(strings.NewReader("hello"), &reqOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatalf("unexpected interruption: %v", it)
	}
	if reqOut.String() != "hello" {
		t.Fatalf("expected passthrough, got %q", reqOut.String())
	}

	// Exercise the response path
	tx.ResponseBodyAccess = false
	tx.AddResponseHeader("Content-Type", "text/plain")
	tx.ProcessResponseHeaders(200, "OK")

	var resOut bytes.Buffer
	it, err = tx.ProcessResponseBodyFromStream(strings.NewReader("world"), &resOut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatalf("unexpected interruption: %v", it)
	}
	if resOut.String() != "world" {
		t.Fatalf("expected passthrough, got %q", resOut.String())
	}
}

// TestProcessBodyFromStreamEngineOff verifies that both request and response
// paths pass through input unchanged when the rule engine is off.
func TestProcessBodyFromStreamEngineOff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request bool
	}{
		{"request", true},
		{"response", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			waf := NewWAF()
			tx := waf.NewTransaction()
			defer tx.Close()
			tx.RuleEngine = types.RuleEngineOff

			var output bytes.Buffer
			var it *types.Interruption
			var err error
			if tc.request {
				it, err = tx.ProcessRequestBodyFromStream(strings.NewReader("passthrough data"), &output)
			} else {
				it, err = tx.ProcessResponseBodyFromStream(strings.NewReader("passthrough data"), &output)
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if it != nil {
				t.Fatal("unexpected interruption when engine is off")
			}
			if output.String() != "passthrough data" {
				t.Fatalf("expected passthrough, got %q", output.String())
			}
		})
	}
}

// --- Exported ProcessRequestBodyFromStream / ProcessResponseBodyFromStream tests ---
//
// These tests register mock body processors in the global registry to exercise
// the full exported code paths including access checks, processor lookup,
// streaming vs non-streaming dispatch, and error propagation.

// capturingStreamProcessor captures BodyProcessorOptions for test assertions.
type capturingStreamProcessor struct {
	mockStreamingBodyProcessor
	capturedOpts plugintypes.BodyProcessorOptions
}

func (c *capturingStreamProcessor) ProcessRequestRecords(r io.Reader, opts plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	c.capturedOpts = opts
	return c.mockStreamingBodyProcessor.ProcessRequestRecords(r, opts, fn)
}

// lastCapturingProcessor holds the most recently created capturingStreamProcessor
// so tests can inspect the options after ProcessRequestBodyFromStream returns.
var lastCapturingProcessor *capturingStreamProcessor

// benchRelayProcessor is the processor used by BenchmarkStreamingRelay.
// The factory registered for "benchstreamrelay" returns this pointer so each
// benchmark sub-case can swap in a different records slice before calling
// ProcessRequestBodyFromStream. Benchmarks run sequentially so there is no
// concurrent access.
var benchRelayProcessor = &benchStreamProcessor{}

func init() {
	// Register a streaming mock body processor for testing.
	bodyprocessors.RegisterBodyProcessor("teststream", func() plugintypes.BodyProcessor {
		return &mockStreamingBodyProcessor{
			records: []mockRecord{
				{fields: map[string]string{"test.0.key": "value"}, rawRecord: []byte("record0\n")},
			},
		}
	})
	// Register a streaming mock that always returns an error after one record.
	bodyprocessors.RegisterBodyProcessor("teststreamerror", func() plugintypes.BodyProcessor {
		return &mockStreamingBodyProcessor{
			records: []mockRecord{
				{fields: map[string]string{"json.0.field": "stale-value"}, rawRecord: []byte("rec\n")},
			},
			err: errors.New("mid-stream processor error"),
		}
	})
	// Register a capturing mock to verify options propagation.
	bodyprocessors.RegisterBodyProcessor("testcapture", func() plugintypes.BodyProcessor {
		p := &capturingStreamProcessor{
			mockStreamingBodyProcessor: mockStreamingBodyProcessor{
				records: []mockRecord{
					{fields: map[string]string{"test.0.key": "value"}, rawRecord: []byte("record0\n")},
				},
			},
		}
		lastCapturingProcessor = p
		return p
	})
	// Register the benchmark relay processor. benchRelayProcessor.records is
	// swapped per sub-benchmark before ProcessRequestBodyFromStream is called.
	bodyprocessors.RegisterBodyProcessor("benchstreamrelay", func() plugintypes.BodyProcessor {
		return benchRelayProcessor
	})
}

// setupRequestStreamTx creates a transaction ready for ProcessRequestBodyFromStream.
func setupRequestStreamTx(t *testing.T, waf *WAF, bodyProcessor string) *Transaction {
	t.Helper()
	tx := waf.NewTransaction()
	tx.RequestBodyAccess = true
	tx.ProcessURI("/test", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddRequestHeader("Content-Type", "application/octet-stream")
	if bodyProcessor != "" {
		tx.variables.reqbodyProcessor.Set(bodyProcessor)
	}
	tx.ProcessRequestHeaders()
	return tx
}

// setupResponseStreamTx creates a transaction ready for ProcessResponseBodyFromStream.
func setupResponseStreamTx(t *testing.T, waf *WAF, bodyProcessor string) *Transaction {
	t.Helper()
	tx := setupRequestStreamTx(t, waf, "")
	tx.RequestBodyAccess = true
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	tx.ResponseBodyAccess = true
	tx.AddResponseHeader("Content-Type", "application/octet-stream")
	tx.ProcessResponseHeaders(200, "OK")
	if bodyProcessor != "" {
		tx.variables.resBodyProcessor.Set(bodyProcessor)
	}
	return tx
}

func TestProcessRequestBodyFromStream(t *testing.T) {
	tests := []struct {
		name          string
		bodyProcessor string
		preInterrupt  bool
		disableAccess bool
		input         string
		wantOutput    string
		wantInterrupt bool
		wantNoOutput  bool
	}{
		{
			name:          "pre-existing interruption returns early with no output",
			bodyProcessor: "TESTSTREAM",
			preInterrupt:  true,
			input:         "data",
			wantInterrupt: true,
			wantNoOutput:  true,
		},
		{
			name:          "no body access passes through",
			bodyProcessor: "TESTSTREAM",
			disableAccess: true,
			input:         "passthrough",
			wantOutput:    "passthrough",
		},
		{
			name:       "no body processor passes through",
			input:      "passthrough",
			wantOutput: "passthrough",
		},
		{
			name:          "invalid processor does not interrupt",
			bodyProcessor: "DOESNOTEXIST",
			input:         "data",
		},
		{
			name:          "streaming processor relays records to output",
			bodyProcessor: "TESTSTREAM",
			wantOutput:    "record0\n",
		},
		{
			name:          "non-streaming processor falls back to buffer",
			bodyProcessor: "URLENCODED",
			input:         "key=value",
			wantOutput:    "key=value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := NewWAF()
			tx := setupRequestStreamTx(t, waf, tt.bodyProcessor)
			defer tx.Close()
			if tt.preInterrupt {
				tx.Interrupt(&types.Interruption{Status: 403, Action: "deny"})
			}
			if tt.disableAccess {
				tx.RequestBodyAccess = false
			}
			var output bytes.Buffer
			it, err := tx.ProcessRequestBodyFromStream(strings.NewReader(tt.input), &output)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantInterrupt && it == nil {
				t.Fatal("expected interruption")
			}
			if !tt.wantInterrupt && it != nil {
				t.Fatalf("unexpected interruption: %v", it)
			}
			if tt.wantNoOutput && output.Len() != 0 {
				t.Fatalf("expected no output, got %q", output.String())
			}
			if tt.wantOutput != "" && output.String() != tt.wantOutput {
				t.Fatalf("expected output %q, got %q", tt.wantOutput, output.String())
			}
		})
	}
}

func TestProcessRequestBodyFromStreamPassesRecursionLimit(t *testing.T) {
	waf := NewWAF()
	waf.RequestBodyJsonDepthLimit = 42
	tx := setupRequestStreamTx(t, waf, "TESTCAPTURE")
	defer tx.Close()

	var output bytes.Buffer
	_, err := tx.ProcessRequestBodyFromStream(strings.NewReader(""), &output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lastCapturingProcessor == nil {
		t.Fatal("capturing processor was not instantiated")
	}
	if got := lastCapturingProcessor.capturedOpts.RequestBodyRecursionLimit; got != 42 {
		t.Fatalf("expected RequestBodyRecursionLimit 42, got %d", got)
	}
}

func TestProcessRequestBodyFromStreamWrongPhase(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()
	// Don't call ProcessRequestHeaders — lastPhase won't be PhaseRequestHeaders

	var output bytes.Buffer
	it, err := tx.ProcessRequestBodyFromStream(strings.NewReader("data"), &output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatalf("unexpected interruption: %v", it)
	}
}

func TestProcessResponseBodyFromStream(t *testing.T) {
	tests := []struct {
		name          string
		bodyProcessor string
		mimeTypes     []string
		preInterrupt  bool
		disableAccess bool
		input         string
		wantOutput    string
		wantInterrupt bool
	}{
		{
			name:          "pre-existing interruption returns early",
			bodyProcessor: "TESTSTREAM",
			preInterrupt:  true,
			input:         "data",
			wantInterrupt: true,
		},
		{
			name:          "no body access passes through",
			bodyProcessor: "TESTSTREAM",
			disableAccess: true,
			input:         "passthrough",
			wantOutput:    "passthrough",
		},
		{
			name:       "no body processor passes through",
			input:      "passthrough",
			wantOutput: "passthrough",
		},
		{
			name:          "invalid processor does not interrupt",
			bodyProcessor: "DOESNOTEXIST",
			mimeTypes:     []string{"application/octet-stream"},
			input:         "data",
		},
		{
			name:          "streaming processor relays records to output",
			bodyProcessor: "TESTSTREAM",
			mimeTypes:     []string{"application/octet-stream"},
			wantOutput:    "record0\n",
		},
		{
			name:          "non-streaming processor falls back to buffer",
			bodyProcessor: "JSON",
			mimeTypes:     []string{"application/octet-stream"},
			input:         `{"key":"value"}`,
			wantOutput:    `{"key":"value"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waf := NewWAF()
			if len(tt.mimeTypes) > 0 {
				waf.ResponseBodyMimeTypes = tt.mimeTypes
			}
			tx := setupResponseStreamTx(t, waf, tt.bodyProcessor)
			defer tx.Close()
			if tt.preInterrupt {
				tx.Interrupt(&types.Interruption{Status: 403, Action: "deny"})
			}
			if tt.disableAccess {
				tx.ResponseBodyAccess = false
			}
			var output bytes.Buffer
			it, err := tx.ProcessResponseBodyFromStream(strings.NewReader(tt.input), &output)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantInterrupt && it == nil {
				t.Fatal("expected interruption")
			}
			if !tt.wantInterrupt && it != nil {
				t.Fatalf("unexpected interruption: %v", it)
			}
			if tt.wantOutput != "" && output.String() != tt.wantOutput {
				t.Fatalf("expected output %q, got %q", tt.wantOutput, output.String())
			}
		})
	}
}

func TestProcessResponseBodyFromStreamWrongPhase(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()

	var output bytes.Buffer
	it, err := tx.ProcessResponseBodyFromStream(strings.NewReader("data"), &output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatalf("unexpected interruption: %v", it)
	}
}

// TestProcessRequestBodyFromStreamErrorClearsArgsPost verifies that the exported
// relay path clears ArgsPost before running fallback Eval after a mid-stream error.
func TestProcessRequestBodyFromStreamErrorClearsArgsPost(t *testing.T) {
	waf := NewWAF()
	tx := setupRequestStreamTx(t, waf, "TESTSTREAMERROR")
	defer tx.Close()

	var output bytes.Buffer
	_, err := tx.ProcessRequestBodyFromStream(strings.NewReader(""), &output)
	if err == nil {
		t.Fatal("expected error from failing stream processor")
	}
	if got := tx.variables.argsPost.Len(); got != 0 {
		t.Fatalf("argsPost not cleared after relay path error: %d entries remain", got)
	}
}

// TestProcessResponseBodyFromStreamErrorClearsResponseArgs verifies that the exported
// relay path clears ResponseArgs before running fallback Eval after a mid-stream error.
func TestProcessResponseBodyFromStreamErrorClearsResponseArgs(t *testing.T) {
	waf := NewWAF()
	waf.ResponseBodyMimeTypes = []string{"application/octet-stream"}
	tx := setupResponseStreamTx(t, waf, "TESTSTREAMERROR")
	defer tx.Close()

	var output bytes.Buffer
	_, err := tx.ProcessResponseBodyFromStream(strings.NewReader(""), &output)
	if err == nil {
		t.Fatal("expected error from failing stream processor")
	}
	if got := tx.variables.responseArgs.Len(); got != 0 {
		t.Fatalf("responseArgs not cleared after relay path error: %d entries remain", got)
	}
}

// --- Binary (protobuf-like) streaming test ---
//
// Demonstrates that the Record interface works for binary formats.
// The wire format is simple length-prefixed messages:
//
//	[4-byte big-endian length][payload bytes]
//
// Each payload contains two "fields" encoded as:
//
//	[1-byte key length][key bytes][2-byte big-endian value length][value bytes]

// binaryRecord implements plugintypes.Record for a length-prefixed binary message.
type binaryRecord struct {
	fields map[string]string
	raw    []byte // the full length-prefixed frame
}

func (r binaryRecord) Fields() map[string]string { return r.fields }
func (r binaryRecord) Raw() []byte               { return r.raw }

// encodeBinaryRecord builds a length-prefixed binary frame from key-value pairs.
func encodeBinaryRecord(fields map[string]string) []byte {
	var payload bytes.Buffer
	for k, v := range fields {
		payload.WriteByte(byte(len(k)))
		payload.WriteString(k)
		_ = binary.Write(&payload, binary.BigEndian, uint16(len(v)))
		payload.WriteString(v)
	}
	frame := make([]byte, 4+payload.Len())
	binary.BigEndian.PutUint32(frame[:4], uint32(payload.Len()))
	copy(frame[4:], payload.Bytes())
	return frame
}

// decodeBinaryRecord parses a length-prefixed binary frame into fields.
func decodeBinaryRecord(frame []byte) (map[string]string, error) {
	if len(frame) < 4 {
		return nil, fmt.Errorf("frame too short")
	}
	payloadLen := binary.BigEndian.Uint32(frame[:4])
	payload := frame[4:]
	if uint32(len(payload)) != payloadLen {
		return nil, fmt.Errorf("payload length mismatch")
	}
	fields := make(map[string]string)
	pos := 0
	for pos < len(payload) {
		keyLen := int(payload[pos])
		pos++
		if pos+keyLen > len(payload) {
			return nil, fmt.Errorf("truncated key")
		}
		key := string(payload[pos : pos+keyLen])
		pos += keyLen
		if pos+2 > len(payload) {
			return nil, fmt.Errorf("truncated value length")
		}
		valLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
		pos += 2
		if pos+valLen > len(payload) {
			return nil, fmt.Errorf("truncated value")
		}
		val := string(payload[pos : pos+valLen])
		pos += valLen
		fields[key] = val
	}
	return fields, nil
}

// binaryStreamProcessor simulates a protobuf-like streaming body processor.
type binaryStreamProcessor struct{}

func (p *binaryStreamProcessor) ProcessRequest(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (p *binaryStreamProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (p *binaryStreamProcessor) ProcessRequestRecords(reader io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	recordNum := 0
	for {
		var lengthBuf [4]byte
		if _, err := io.ReadFull(reader, lengthBuf[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		payloadLen := binary.BigEndian.Uint32(lengthBuf[:])
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return fmt.Errorf("truncated record %d: %w", recordNum, err)
		}
		frame := make([]byte, 4+payloadLen)
		copy(frame[:4], lengthBuf[:])
		copy(frame[4:], payload)
		fields, err := decodeBinaryRecord(frame)
		if err != nil {
			return fmt.Errorf("record %d: %w", recordNum, err)
		}
		prefixed := make(map[string]string, len(fields))
		for k, v := range fields {
			prefixed[fmt.Sprintf("proto.%d.%s", recordNum, k)] = v
		}
		if err := fn(recordNum, binaryRecord{fields: prefixed, raw: frame}); err != nil {
			return err
		}
		recordNum++
	}
}

func (p *binaryStreamProcessor) ProcessResponseRecords(reader io.Reader, opts plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	return p.ProcessRequestRecords(reader, opts, fn)
}

func TestProcessRequestBodyStreamingBinaryFormat(t *testing.T) {
	waf := NewWAF()
	rule := newStreamingTestRule(t, 700, variables.ArgsPost, "malicious", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	var stream bytes.Buffer
	stream.Write(encodeBinaryRecord(map[string]string{"user": "alice", "role": "admin"}))
	stream.Write(encodeBinaryRecord(map[string]string{"user": "malicious-actor", "role": "root"}))
	stream.Write(encodeBinaryRecord(map[string]string{"user": "bob", "role": "viewer"}))

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	it, err := tx.processRequestBodyStreaming(&binaryStreamProcessor{}, &stream, plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it == nil {
		t.Fatal("expected interruption for malicious binary record")
	}
}

func TestBinaryStreamProcessorUnexpectedEOFIsError(t *testing.T) {
	// A truncated frame header (fewer than 4 bytes) must be reported as an error,
	// not silently treated as a clean end-of-stream.
	truncatedHeader := []byte{0x00, 0x00} // only 2 of 4 header bytes
	sp := &binaryStreamProcessor{}
	var called bool
	err := sp.ProcessRequestRecords(bytes.NewReader(truncatedHeader), plugintypes.BodyProcessorOptions{},
		func(_ int, _ plugintypes.Record) error {
			called = true
			return nil
		})
	if err == nil {
		t.Fatal("expected error for truncated frame header, got nil")
	}
	if called {
		t.Fatal("callback should not have been called for truncated header")
	}
}

// --- Benchmarks ---

// benchRecord holds precomputed data for one record.
type benchRecord struct {
	fields map[string]string
	raw    []byte
}

func makeBenchRecords(n, fieldsPerRecord, valueSize int) []benchRecord {
	val := strings.Repeat("x", valueSize)
	records := make([]benchRecord, n)
	for i := range n {
		fields := make(map[string]string, fieldsPerRecord)
		for f := range fieldsPerRecord {
			key := fmt.Sprintf("json.%d.field%d", i, f)
			fields[key] = val
		}
		var raw bytes.Buffer
		raw.WriteString(`{"i":`)
		raw.WriteString(strconv.Itoa(i))
		for f := range fieldsPerRecord {
			fmt.Fprintf(&raw, `,"field%d":"%s"`, f, val)
		}
		raw.WriteString("}\n")
		records[i] = benchRecord{fields: fields, raw: raw.Bytes()}
	}
	return records
}

type bufferedProcessor struct {
	records []benchRecord
}

func (p *bufferedProcessor) ProcessRequest(_ io.Reader, tv plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	for _, rec := range p.records {
		for key, value := range rec.fields {
			tv.ArgsPost().SetIndex(key, 0, value)
		}
	}
	return nil
}

func (p *bufferedProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

type benchStreamProcessor struct {
	records []benchRecord
}

func (p *benchStreamProcessor) ProcessRequest(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (p *benchStreamProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (p *benchStreamProcessor) ProcessRequestRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(int, plugintypes.Record) error) error {
	for i, rec := range p.records {
		if err := fn(i, mockRecord{fields: rec.fields, rawRecord: rec.raw}); err != nil {
			return err
		}
	}
	return nil
}

func (p *benchStreamProcessor) ProcessResponseRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(int, plugintypes.Record) error) error {
	return p.ProcessRequestRecords(nil, plugintypes.BodyProcessorOptions{}, fn)
}

func newBenchWAF(b *testing.B) *WAF {
	b.Helper()
	waf := NewWAF()
	patterns := []string{
		`(?i)select\b.*\bfrom\b`,
		`<script[^>]*>`,
		`\.\./`,
		`\b(?:cmd|exec|system)\s*\(`,
		`(?i)union\b.*\bselect\b`,
	}
	for i, pat := range patterns {
		rule := NewRule()
		rule.ID_ = 900 + i
		rule.LogID_ = strconv.Itoa(900 + i)
		rule.Phase_ = types.PhaseRequestBody
		op, err := operators.Get("rx", plugintypes.OperatorOptions{Arguments: pat})
		if err != nil {
			b.Fatal(err)
		}
		rule.operator = &ruleOperatorParams{Operator: op, Function: "@rx", Data: pat}
		rule.variables = append(rule.variables, ruleVariableParams{Variable: variables.ArgsPost})
		if err := waf.Rules.Add(rule); err != nil {
			b.Fatal(err)
		}
	}
	return waf
}

// BenchmarkStreamingEval measures the per-record streaming evaluation path.
//
//	go test -bench=BenchmarkStreamingEval -benchmem ./internal/corazawaf/
func BenchmarkStreamingEval(b *testing.B) {
	cases := []struct {
		name            string
		numRecords      int
		fieldsPerRecord int
		valueSize       int
	}{
		{"small/10rec", 10, 3, 24},
		{"medium/100rec", 100, 5, 64},
		{"large/1000rec", 1000, 5, 128},
	}

	for _, tc := range cases {
		records := makeBenchRecords(tc.numRecords, tc.fieldsPerRecord, tc.valueSize)

		b.Run("streaming/"+tc.name, func(b *testing.B) {
			waf := newBenchWAF(b)
			sp := &benchStreamProcessor{records: records}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				tx := waf.NewTransaction()
				tx.RequestBodyAccess = true
				_, _ = tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
				_ = tx.Close()
			}
		})

		b.Run("buffered/"+tc.name, func(b *testing.B) {
			waf := newBenchWAF(b)
			bp := &bufferedProcessor{records: records}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				tx := waf.NewTransaction()
				tx.RequestBodyAccess = true
				_ = bp.ProcessRequest(strings.NewReader(""), tx.Variables(), plugintypes.BodyProcessorOptions{})
				waf.Rules.Eval(types.PhaseRequestBody, tx)
				_ = tx.Close()
			}
		})
	}
}

// BenchmarkStreamingRelay measures the relay path through ProcessRequestBodyFromStream,
// exercising processor lookup, access gating, option propagation, and the
// full per-record evaluate-then-write loop.
//
//	go test -bench=BenchmarkStreamingRelay -benchmem ./internal/corazawaf/
func BenchmarkStreamingRelay(b *testing.B) {
	cases := []struct {
		name            string
		numRecords      int
		fieldsPerRecord int
		valueSize       int
	}{
		{"small/10rec", 10, 3, 24},
		{"medium/100rec", 100, 5, 64},
		{"large/1000rec", 1000, 5, 128},
	}

	for _, tc := range cases {
		records := makeBenchRecords(tc.numRecords, tc.fieldsPerRecord, tc.valueSize)
		totalRaw := 0
		for _, r := range records {
			totalRaw += len(r.raw)
		}

		b.Run(tc.name, func(b *testing.B) {
			waf := newBenchWAF(b)
			// Point the global factory at the records for this sub-case.
			benchRelayProcessor.records = records
			b.SetBytes(int64(totalRaw))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				tx := waf.NewTransaction()
				tx.RequestBodyAccess = true
				// Set lastPhase so ProcessRequestBodyFromStream passes the phase gate
				// without the overhead of a full ProcessRequestHeaders call.
				tx.lastPhase = types.PhaseRequestHeaders
				tx.variables.reqbodyProcessor.Set("benchstreamrelay")
				var output bytes.Buffer
				output.Grow(totalRaw)
				_, _ = tx.ProcessRequestBodyFromStream(nil, &output)
				_ = tx.Close()
			}
		})
	}
}

// BenchmarkStreamingBinaryFormat measures the binary (protobuf-like) streaming path.
//
//	go test -bench=BenchmarkStreamingBinaryFormat -benchmem ./internal/corazawaf/
func BenchmarkStreamingBinaryFormat(b *testing.B) {
	cases := []struct {
		name       string
		numRecords int
		fields     map[string]string
	}{
		{"small/10rec", 10, map[string]string{"id": "42", "status": "ok"}},
		{"medium/100rec", 100, map[string]string{
			"id": "42", "user": "alice", "role": "admin",
			"email": "alice@example.com", "active": "true",
		}},
		{"large/1000rec", 1000, map[string]string{
			"id": "42", "user": "alice", "role": "admin",
			"email": "alice@example.com", "active": "true",
		}},
	}

	for _, tc := range cases {
		var stream bytes.Buffer
		for range tc.numRecords {
			stream.Write(encodeBinaryRecord(tc.fields))
		}
		streamBytes := stream.Bytes()

		b.Run(tc.name, func(b *testing.B) {
			waf := newBenchWAF(b)
			sp := &binaryStreamProcessor{}
			b.SetBytes(int64(len(streamBytes)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				tx := waf.NewTransaction()
				tx.RequestBodyAccess = true
				reader := bytes.NewReader(streamBytes)
				_, _ = tx.processRequestBodyStreaming(sp, reader, plugintypes.BodyProcessorOptions{})
				_ = tx.Close()
			}
		})
	}
}
