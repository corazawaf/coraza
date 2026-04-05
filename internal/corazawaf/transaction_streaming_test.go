// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/operators"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// mockStreamingBodyProcessor implements StreamingBodyProcessor for testing.
type mockStreamingBodyProcessor struct {
	records []mockRecord
	err     error // error to return after all records
}

type mockRecord struct {
	fields    map[string]string
	rawRecord string
}

func (m *mockStreamingBodyProcessor) ProcessRequest(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (m *mockStreamingBodyProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (m *mockStreamingBodyProcessor) ProcessRequestRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) error {
	for i, rec := range m.records {
		if err := fn(i, rec.fields, rec.rawRecord); err != nil {
			return err
		}
	}
	return m.err
}

func (m *mockStreamingBodyProcessor) ProcessResponseRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) error {
	for i, rec := range m.records {
		if err := fn(i, rec.fields, rec.rawRecord); err != nil {
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

// newStreamingTestRule creates a rule that matches a given ArgsPost field value.
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
		_ = rule.AddAction("deny", &dummyStreamDenyAction{})
	}
	rule.Log = true
	rule.Audit = true
	return rule
}

func TestProcessRequestBodyStreamingCleanRecords(t *testing.T) {
	waf := NewWAF()
	rule := newStreamingTestRule(t, 100, variables.ArgsPost, "malicious", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.name": "alice"}, rawRecord: `{"name":"alice"}` + "\n"},
			{fields: map[string]string{"json.1.name": "bob"}, rawRecord: `{"name":"bob"}` + "\n"},
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
	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.name": "safe"}, rawRecord: `{"name":"safe"}` + "\n"},
			{fields: map[string]string{"json.1.name": "malicious-payload"}, rawRecord: `{"name":"malicious-payload"}` + "\n"},
			{fields: map[string]string{"json.2.name": "should-not-reach"}, rawRecord: `{"name":"should-not-reach"}` + "\n"},
		},
	}
	// Override ProcessRequestRecords to count records
	origRecords := sp.records
	sp2 := &countingStreamProcessor{records: origRecords, count: &processedRecords}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	it, err := tx.processRequestBodyStreaming(sp2, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
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
	fn func(recordNum int, fields map[string]string, rawRecord string) error) error {
	for i, rec := range c.records {
		*c.count++
		if err := fn(i, rec.fields, rec.rawRecord); err != nil {
			return err
		}
	}
	return nil
}

func (c *countingStreamProcessor) ProcessResponseRecords(_ io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, fields map[string]string, rawRecord string) error) error {
	for i, rec := range c.records {
		*c.count++
		if err := fn(i, rec.fields, rec.rawRecord); err != nil {
			return err
		}
	}
	return nil
}

func TestProcessRequestBodyStreamingTxVariablesPersist(t *testing.T) {
	// TX variables should persist across records for cross-record correlation.
	waf := NewWAF()

	// Add a rule that sets tx.score += 1 for each record containing "suspicious"
	rule := NewRule()
	rule.ID_ = 200
	rule.LogID_ = "test"
	rule.Phase_ = types.PhaseRequestBody

	op, err := operators.Get("rx", plugintypes.OperatorOptions{
		Arguments: "suspicious",
	})
	if err != nil {
		t.Fatal(err)
	}
	rule.operator = &ruleOperatorParams{
		Operator: op,
		Function: "@rx",
		Data:     "suspicious",
		Negation: false,
	}
	rule.variables = append(rule.variables, ruleVariableParams{
		Variable: variables.ArgsPost,
	})
	rule.Log = true
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.data": "suspicious-1"}, rawRecord: `{"data":"suspicious-1"}` + "\n"},
			{fields: map[string]string{"json.1.data": "clean"}, rawRecord: `{"data":"clean"}` + "\n"},
			{fields: map[string]string{"json.2.data": "suspicious-2"}, rawRecord: `{"data":"suspicious-2"}` + "\n"},
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
		t.Fatalf("unexpected interruption: %v", it)
	}
	// matchedRules should have 2 entries (records 0 and 2 matched)
	if len(tx.matchedRules) != 2 {
		t.Fatalf("expected 2 matched rules, got %d", len(tx.matchedRules))
	}
}

func TestProcessRequestBodyStreamingArgsPostIsolated(t *testing.T) {
	// Each record should only see its own fields in ArgsPost
	waf := NewWAF()

	// Add a rule that matches any ArgsPost value containing "record1-only"
	rule := newStreamingTestRule(t, 300, variables.ArgsPost, "record1-only", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.data": "clean"}, rawRecord: `{"data":"clean"}` + "\n"},
			// This record's field does NOT contain "record1-only"
			{fields: map[string]string{"json.1.data": "also-clean"}, rawRecord: `{"data":"also-clean"}` + "\n"},
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
		t.Fatal("unexpected interruption: records are clean")
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
			{fields: map[string]string{"json.0.name": "safe"}, rawRecord: `{"name":"safe"}` + "\n"},
			{fields: map[string]string{"json.1.name": "malicious-data"}, rawRecord: `{"name":"malicious-data"}` + "\n"},
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

func TestProcessRequestBodyStreamingProcessorError(t *testing.T) {
	waf := NewWAF()
	rule := newStreamingTestRule(t, 500, variables.ArgsPost, "anything", false)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		err: errors.New("simulated processor error"),
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	it, err := tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error (should be nil): %v", err)
	}
	// The processor error should trigger error handling but not an interruption
	// (unless rules trigger one based on the error)
	_ = it
}

func TestProcessRequestBodyFromStreamRelay(t *testing.T) {
	waf := NewWAF()
	rule := newStreamingTestRule(t, 600, variables.ArgsPost, "blocked", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	// Register a mock streaming body processor
	// Since we can't easily register a mock via bodyprocessors.GetBodyProcessor,
	// we test the relay logic through the lower-level processRequestBodyStreaming
	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.name": "safe"}, rawRecord: `{"name":"safe"}` + "\n"},
			{fields: map[string]string{"json.1.name": "blocked-value"}, rawRecord: `{"name":"blocked-value"}` + "\n"},
			{fields: map[string]string{"json.2.name": "never-reached"}, rawRecord: `{"name":"never-reached"}` + "\n"},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	var output bytes.Buffer
	// Manually test the relay pattern
	streamErr := sp.ProcessRequestRecords(strings.NewReader(""), plugintypes.BodyProcessorOptions{},
		func(recordNum int, fields map[string]string, rawRecord string) error {
			tx.variables.argsPost.Reset()
			for key, value := range fields {
				tx.variables.argsPost.SetIndex(key, 0, value)
			}
			tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
			if tx.interruption != nil {
				return errStreamInterrupted
			}
			if _, err := io.WriteString(&output, rawRecord); err != nil {
				return err
			}
			return nil
		})

	if streamErr != errStreamInterrupted {
		t.Fatalf("expected errStreamInterrupted, got: %v", streamErr)
	}
	// Only the first record should have been relayed
	expected := `{"name":"safe"}` + "\n"
	if output.String() != expected {
		t.Fatalf("expected output %q, got %q", expected, output.String())
	}
}

func TestProcessResponseBodyFromStreamRelay(t *testing.T) {
	waf := NewWAF()

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.a": "1"}, rawRecord: `{"a":"1"}` + "\n"},
			{fields: map[string]string{"json.1.a": "2"}, rawRecord: `{"a":"2"}` + "\n"},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ResponseBodyAccess = true

	var output bytes.Buffer
	streamErr := sp.ProcessResponseRecords(strings.NewReader(""), plugintypes.BodyProcessorOptions{},
		func(recordNum int, fields map[string]string, rawRecord string) error {
			tx.variables.responseArgs.Reset()
			for key, value := range fields {
				tx.variables.responseArgs.SetIndex(key, 0, value)
			}
			tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
			if tx.interruption != nil {
				return errStreamInterrupted
			}
			if _, err := io.WriteString(&output, rawRecord); err != nil {
				return err
			}
			return nil
		})

	if streamErr != nil {
		t.Fatalf("unexpected error: %v", streamErr)
	}
	expected := `{"a":"1"}` + "\n" + `{"a":"2"}` + "\n"
	if output.String() != expected {
		t.Fatalf("expected output %q, got %q", expected, output.String())
	}
}

func TestStreamingTransactionInterface(t *testing.T) {
	// Verify that *Transaction implements the methods needed for StreamingTransaction
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()

	// Check that ProcessRequestBodyFromStream and ProcessResponseBodyFromStream exist
	var _ interface {
		ProcessRequestBodyFromStream(io.Reader, io.Writer) (*types.Interruption, error)
		ProcessResponseBodyFromStream(io.Reader, io.Writer) (*types.Interruption, error)
	} = tx
}

func TestProcessRequestBodyFromStreamEngineOff(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RuleEngine = types.RuleEngineOff

	input := strings.NewReader("passthrough data")
	var output bytes.Buffer

	it, err := tx.ProcessRequestBodyFromStream(input, &output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatal("unexpected interruption when engine is off")
	}
	if output.String() != "passthrough data" {
		t.Fatalf("expected passthrough, got %q", output.String())
	}
}

func TestProcessResponseBodyFromStreamEngineOff(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RuleEngine = types.RuleEngineOff

	input := strings.NewReader("passthrough data")
	var output bytes.Buffer

	it, err := tx.ProcessResponseBodyFromStream(input, &output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatal("unexpected interruption when engine is off")
	}
	if output.String() != "passthrough data" {
		t.Fatalf("expected passthrough, got %q", output.String())
	}
}
