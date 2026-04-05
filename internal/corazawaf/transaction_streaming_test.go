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
		if err := rule.AddAction("deny", &dummyStreamDenyAction{}); err != nil {
			t.Fatalf("add deny action: %v", err)
		}
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
	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			{fields: map[string]string{"json.0.name": "safe"}, rawRecord: []byte(`{"name":"safe"}` + "\n")},
			{fields: map[string]string{"json.1.name": "malicious-payload"}, rawRecord: []byte(`{"name":"malicious-payload"}` + "\n")},
			{fields: map[string]string{"json.2.name": "should-not-reach"}, rawRecord: []byte(`{"name":"should-not-reach"}` + "\n")},
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

	// Set a TX variable before streaming — it should survive all records
	tx.variables.tx.SetIndex("marker", 0, "persist-me")

	it, err := tx.processRequestBodyStreaming(sp, strings.NewReader(""), plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it != nil {
		t.Fatalf("unexpected interruption: %v", it)
	}

	// matchedRules accumulates across records (TX-scoped): 2 matches (records 0 and 2)
	if len(tx.matchedRules) != 2 {
		t.Fatalf("expected 2 matched rules, got %d", len(tx.matchedRules))
	}

	// TX variable set before streaming should still be present
	if vals := tx.variables.tx.Get("marker"); len(vals) == 0 || vals[0] != "persist-me" {
		t.Fatalf("TX variable 'marker' did not persist across records, got: %v", vals)
	}
}

func TestProcessRequestBodyStreamingArgsPostIsolated(t *testing.T) {
	// Verify that record 0's fields don't leak into record 1's evaluation.
	// The rule matches "record0-only" which appears only in record 0.
	// If ArgsPost is not properly reset between records, record 1 would
	// also match and cause an interruption.
	waf := NewWAF()

	rule := newStreamingTestRule(t, 300, variables.ArgsPost, "record0-only", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	sp := &mockStreamingBodyProcessor{
		records: []mockRecord{
			// Record 0: contains the pattern — will match, but deny is not triggered
			// because the rule is re-evaluated per record and we want to check isolation.
			// Actually, with deny=true the first record WILL interrupt. So use deny=false
			// and check matchedRules instead.
			{fields: map[string]string{"json.0.data": "record0-only-value"}, rawRecord: []byte(`{"data":"record0-only-value"}` + "\n")},
			// Record 1: does NOT contain "record0-only" — should NOT match
			{fields: map[string]string{"json.1.data": "clean"}, rawRecord: []byte(`{"data":"clean"}` + "\n")},
		},
	}

	// Rebuild with deny=false so processing continues through both records
	waf2 := NewWAF()
	rule2 := newStreamingTestRule(t, 300, variables.ArgsPost, "record0-only", false)
	if err := waf2.Rules.Add(rule2); err != nil {
		t.Fatal(err)
	}

	tx := waf2.NewTransaction()
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
			{fields: map[string]string{"json.0.name": "safe"}, rawRecord: []byte(`{"name":"safe"}` + "\n")},
			{fields: map[string]string{"json.1.name": "blocked-value"}, rawRecord: []byte(`{"name":"blocked-value"}` + "\n")},
			{fields: map[string]string{"json.2.name": "never-reached"}, rawRecord: []byte(`{"name":"never-reached"}` + "\n")},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	var output bytes.Buffer
	// Manually test the relay pattern
	streamErr := sp.ProcessRequestRecords(strings.NewReader(""), plugintypes.BodyProcessorOptions{},
		func(recordNum int, record plugintypes.Record) error {
			tx.variables.argsPost.Reset()
			for key, value := range record.Fields() {
				tx.variables.argsPost.SetIndex(key, 0, value)
			}
			tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
			if tx.interruption != nil {
				return errStreamInterrupted
			}
			if _, err := output.Write(record.Raw()); err != nil {
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
			{fields: map[string]string{"json.0.a": "1"}, rawRecord: []byte(`{"a":"1"}` + "\n")},
			{fields: map[string]string{"json.1.a": "2"}, rawRecord: []byte(`{"a":"2"}` + "\n")},
		},
	}

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ResponseBodyAccess = true

	var output bytes.Buffer
	streamErr := sp.ProcessResponseRecords(strings.NewReader(""), plugintypes.BodyProcessorOptions{},
		func(recordNum int, record plugintypes.Record) error {
			tx.variables.responseArgs.Reset()
			for key, value := range record.Fields() {
				tx.variables.responseArgs.SetIndex(key, 0, value)
			}
			tx.WAF.Rules.Eval(types.PhaseResponseBody, tx)
			if tx.interruption != nil {
				return errStreamInterrupted
			}
			if _, err := output.Write(record.Raw()); err != nil {
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
	// Verify that *Transaction satisfies the StreamingTransaction contract
	// by actually exercising the exported methods (not just a type assertion).
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()

	// Compile-time interface check
	var _ interface {
		ProcessRequestBodyFromStream(io.Reader, io.Writer) (*types.Interruption, error)
		ProcessResponseBodyFromStream(io.Reader, io.Writer) (*types.Interruption, error)
	} = tx

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
//
// This is NOT real protobuf, but exercises the same properties: binary
// framing, non-UTF-8 raw bytes, and string-based field extraction.

// binaryRecord implements plugintypes.Record for a length-prefixed binary message.
type binaryRecord struct {
	fields map[string]string
	raw    []byte // the full length-prefixed frame
}

func (r binaryRecord) Fields() map[string]string { return r.fields }
func (r binaryRecord) Raw() []byte               { return r.raw }

// encodeBinaryRecord builds a length-prefixed binary frame from key-value pairs.
// The payload format per field: [1-byte keyLen][key][2-byte valueLen][value].
func encodeBinaryRecord(fields map[string]string) []byte {
	var payload bytes.Buffer
	for k, v := range fields {
		payload.WriteByte(byte(len(k)))
		payload.WriteString(k)
		_ = binary.Write(&payload, binary.BigEndian, uint16(len(v)))
		payload.WriteString(v)
	}
	// Frame: [4-byte length][payload]
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
		if pos >= len(payload) {
			break
		}
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

// binaryStreamProcessor simulates a protobuf-like streaming body processor
// that reads length-prefixed binary messages from a reader.
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
		// Read 4-byte length prefix
		var lengthBuf [4]byte
		if _, err := io.ReadFull(reader, lengthBuf[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil // end of stream
			}
			return err
		}
		payloadLen := binary.BigEndian.Uint32(lengthBuf[:])

		// Read payload
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return fmt.Errorf("truncated record %d: %w", recordNum, err)
		}

		// Full frame = length prefix + payload
		frame := make([]byte, 4+payloadLen)
		copy(frame[:4], lengthBuf[:])
		copy(frame[4:], payload)

		// Decode fields (the "protobuf deserialization")
		fields, err := decodeBinaryRecord(frame)
		if err != nil {
			return fmt.Errorf("record %d: %w", recordNum, err)
		}

		// Prefix field keys with record number
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
	// Block any record containing "malicious" in ArgsPost
	rule := newStreamingTestRule(t, 700, variables.ArgsPost, "malicious", true)
	if err := waf.Rules.Add(rule); err != nil {
		t.Fatal(err)
	}

	// Build a binary stream: 3 records, second one is malicious
	var stream bytes.Buffer
	stream.Write(encodeBinaryRecord(map[string]string{"user": "alice", "role": "admin"}))
	stream.Write(encodeBinaryRecord(map[string]string{"user": "malicious-actor", "role": "root"}))
	stream.Write(encodeBinaryRecord(map[string]string{"user": "bob", "role": "viewer"}))

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	sp := &binaryStreamProcessor{}

	it, err := tx.processRequestBodyStreaming(sp, &stream, plugintypes.BodyProcessorOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if it == nil {
		t.Fatal("expected interruption for malicious binary record")
	}
}

func TestProcessRequestBodyStreamingBinaryRelay(t *testing.T) {
	waf := NewWAF()
	// No deny rules — all records pass through
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true

	// Build a binary stream with 2 clean records
	rec1 := encodeBinaryRecord(map[string]string{"id": "1", "status": "ok"})
	rec2 := encodeBinaryRecord(map[string]string{"id": "2", "status": "ok"})
	var stream bytes.Buffer
	stream.Write(rec1)
	stream.Write(rec2)

	sp := &binaryStreamProcessor{}

	var output bytes.Buffer
	err := sp.ProcessRequestRecords(&stream, plugintypes.BodyProcessorOptions{},
		func(recordNum int, record plugintypes.Record) error {
			tx.variables.argsPost.Reset()
			for key, value := range record.Fields() {
				tx.variables.argsPost.SetIndex(key, 0, value)
			}
			tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
			if tx.interruption != nil {
				return errStreamInterrupted
			}
			if _, err := output.Write(record.Raw()); err != nil {
				return err
			}
			return nil
		})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Output should be the exact binary frames concatenated
	expected := make([]byte, 0, len(rec1)+len(rec2))
	expected = append(expected, rec1...)
	expected = append(expected, rec2...)
	if !bytes.Equal(output.Bytes(), expected) {
		t.Fatalf("binary relay mismatch:\n  got:  %x\n  want: %x", output.Bytes(), expected)
	}

	// Verify the frames can be decoded back
	fields1, err := decodeBinaryRecord(rec1)
	if err != nil {
		t.Fatal(err)
	}
	if fields1["id"] != "1" || fields1["status"] != "ok" {
		t.Fatalf("unexpected fields in relayed record 1: %v", fields1)
	}
}

// --- Benchmarks ---
//
// These benchmarks measure the per-record streaming evaluation path against
// the traditional buffered ProcessRequest path across different stream sizes
// and record complexities.

// benchRecord holds precomputed data for one record.
type benchRecord struct {
	fields map[string]string
	raw    []byte
}

// makeBenchRecords generates n records. Each record has the given number of
// fields with values of the specified size.
func makeBenchRecords(n, fieldsPerRecord, valueSize int) []benchRecord {
	val := strings.Repeat("x", valueSize)
	records := make([]benchRecord, n)
	for i := range n {
		fields := make(map[string]string, fieldsPerRecord)
		for f := range fieldsPerRecord {
			key := fmt.Sprintf("json.%d.field%d", i, f)
			fields[key] = val
		}
		// Simulate raw record: a JSON-like line
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

// bufferedProcessor implements BodyProcessor (non-streaming). It populates
// TransactionVariables with all records at once, simulating the traditional
// full-body parsing approach.
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

// benchStreamProcessor implements StreamingBodyProcessor from precomputed records.
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

// newBenchWAF creates a WAF with a realistic set of Phase 2 rules that inspect
// ArgsPost via @rx. The patterns don't match the bench data, so no interruption
// occurs — this measures steady-state evaluation cost.
func newBenchWAF(b *testing.B) *WAF {
	b.Helper()
	waf := NewWAF()
	patterns := []string{
		`(?i)select\b.*\bfrom\b`,     // SQLi
		`<script[^>]*>`,              // XSS
		`\.\./`,                      // path traversal
		`\b(?:cmd|exec|system)\s*\(`, // command injection
		`(?i)union\b.*\bselect\b`,    // SQLi union
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
	type benchCase struct {
		name            string
		numRecords      int
		fieldsPerRecord int
		valueSize       int
	}
	cases := []benchCase{
		// Small: 10 records × 3 fields × 24-byte values (~720 B payload)
		{"small/10rec", 10, 3, 24},
		// Medium: 100 records × 5 fields × 64-byte values (~32 KB payload)
		{"medium/100rec", 100, 5, 64},
		// Large: 1000 records × 5 fields × 128-byte values (~640 KB payload)
		{"large/1000rec", 1000, 5, 128},
	}

	for _, tc := range cases {
		records := makeBenchRecords(tc.numRecords, tc.fieldsPerRecord, tc.valueSize)

		// --- Streaming path: per-record evaluation ---
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

		// --- Buffered path: load all fields then evaluate once ---
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

// BenchmarkStreamingRelay measures the relay path (evaluate + write to output).
//
//	go test -bench=BenchmarkStreamingRelay -benchmem ./internal/corazawaf/
func BenchmarkStreamingRelay(b *testing.B) {
	type benchCase struct {
		name            string
		numRecords      int
		fieldsPerRecord int
		valueSize       int
	}
	cases := []benchCase{
		{"small/10rec", 10, 3, 24},
		{"medium/100rec", 100, 5, 64},
		{"large/1000rec", 1000, 5, 128},
	}

	for _, tc := range cases {
		records := makeBenchRecords(tc.numRecords, tc.fieldsPerRecord, tc.valueSize)
		// Precompute total raw size for buffer preallocation
		totalRaw := 0
		for _, r := range records {
			totalRaw += len(r.raw)
		}

		b.Run(tc.name, func(b *testing.B) {
			waf := newBenchWAF(b)
			sp := &benchStreamProcessor{records: records}
			b.SetBytes(int64(totalRaw))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				tx := waf.NewTransaction()
				tx.RequestBodyAccess = true
				var output bytes.Buffer
				output.Grow(totalRaw)
				_ = sp.ProcessRequestRecords(nil, plugintypes.BodyProcessorOptions{},
					func(recordNum int, record plugintypes.Record) error {
						tx.variables.argsPost.Reset()
						for key, value := range record.Fields() {
							tx.variables.argsPost.SetIndex(key, 0, value)
						}
						tx.WAF.Rules.Eval(types.PhaseRequestBody, tx)
						if tx.interruption != nil {
							return errStreamInterrupted
						}
						_, _ = output.Write(record.Raw())
						return nil
					})
				_ = tx.Close()
			}
		})
	}
}

// BenchmarkStreamingBinaryFormat measures the binary (protobuf-like) streaming path
// including the decode cost.
//
//	go test -bench=BenchmarkStreamingBinaryFormat -benchmem ./internal/corazawaf/
func BenchmarkStreamingBinaryFormat(b *testing.B) {
	type benchCase struct {
		name       string
		numRecords int
		fields     map[string]string
	}
	cases := []benchCase{
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
		// Build binary stream
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
