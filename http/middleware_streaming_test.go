// Copyright 2026 OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package http

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// --- Test streaming body processor ---
//
// Simulates a simple line-delimited format (like NDJSON) where each line is a
// record. The processor splits on newlines, extracts key=value pairs separated
// by commas, and yields them as Records with "stream.N.key" prefixed field keys.

type testStreamRecord struct {
	fields map[string]string
	raw    []byte
}

func (r testStreamRecord) Fields() map[string]string { return r.fields }
func (r testStreamRecord) Raw() []byte               { return r.raw }

type testStreamProcessor struct{}

func (p *testStreamProcessor) ProcessRequest(reader io.Reader, vars plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	// Buffered fallback: parse all lines at once
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	recordNum := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, pair := range strings.Split(line, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				vars.ArgsPost().SetIndex("stream."+strconv.Itoa(recordNum)+"."+key, 0, val)
			}
		}
		recordNum++
	}
	return nil
}

func (p *testStreamProcessor) ProcessResponse(_ io.Reader, _ plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	return nil
}

func (p *testStreamProcessor) ProcessRequestRecords(reader io.Reader, _ plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	scanner := bufio.NewScanner(reader)
	recordNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := make(map[string]string)
		for _, pair := range strings.Split(line, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				fields["stream."+strconv.Itoa(recordNum)+"."+key] = val
			}
		}
		raw := append([]byte(line), '\n')
		if err := fn(recordNum, testStreamRecord{fields: fields, raw: raw}); err != nil {
			return err
		}
		recordNum++
	}
	return scanner.Err()
}

func (p *testStreamProcessor) ProcessResponseRecords(reader io.Reader, opts plugintypes.BodyProcessorOptions,
	fn func(recordNum int, record plugintypes.Record) error) error {
	return p.ProcessRequestRecords(reader, opts, fn)
}

func init() {
	plugins.RegisterBodyProcessor("teststream", func() plugintypes.BodyProcessor {
		return &testStreamProcessor{}
	})
}

// TestStreamingMiddlewareCleanRecordsPassThrough verifies that a stream of clean
// records passes through the WAF middleware without interruption and the backend
// handler receives the full body.
func TestStreamingMiddlewareCleanRecordsPassThrough(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRule REQUEST_HEADERS:Content-Type "text/csv" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=TESTSTREAM"
			SecRule ARGS_POST "@rx malicious" "id:100,phase:2,deny,status:403,log,msg:'Malicious content'"
		`).
		WithErrorCallback(errLogger(t)))
	if err != nil {
		t.Fatal(err)
	}

	var backendBody string
	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		backendBody = string(body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	body := "user=alice,role=admin\nuser=bob,role=viewer\nuser=charlie,role=editor\n"
	req, _ := http.NewRequest("POST", ts.URL+"/api/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/csv")

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	resBody, _ := io.ReadAll(res.Body)
	if string(resBody) != "OK" {
		t.Fatalf("unexpected response body: %q", string(resBody))
	}

	// The backend should have received the body (buffered by the middleware)
	if backendBody == "" {
		t.Fatal("backend received empty body")
	}
}

// TestStreamingMiddlewareMaliciousRecordBlocked verifies that when one record
// in a stream matches a deny rule, the WAF interrupts the request and returns
// 403 without letting the malicious record reach the backend.
func TestStreamingMiddlewareMaliciousRecordBlocked(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRule REQUEST_HEADERS:Content-Type "text/csv" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=TESTSTREAM"
			SecRule ARGS_POST "@rx malicious" "id:100,phase:2,deny,status:403,log,msg:'Malicious content'"
		`).
		WithErrorCallback(errLogger(t)))
	if err != nil {
		t.Fatal(err)
	}

	var backendCalled bool
	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Second record contains "malicious" — should trigger deny
	body := "user=alice,role=admin\nuser=malicious-actor,role=root\nuser=bob,role=viewer\n"
	req, _ := http.NewRequest("POST", ts.URL+"/api/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/csv")

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}

	if backendCalled {
		t.Fatal("backend should not have been called when request is blocked")
	}
}

// TestStreamingMiddlewareFirstRecordBlocked verifies that even the very first
// record can trigger a deny — the WAF doesn't need to see multiple records
// before it can block.
func TestStreamingMiddlewareFirstRecordBlocked(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRule REQUEST_HEADERS:Content-Type "text/csv" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=TESTSTREAM"
			SecRule ARGS_POST "@rx attack" "id:100,phase:2,deny,status:403"
		`).
		WithErrorCallback(errLogger(t)))
	if err != nil {
		t.Fatal(err)
	}

	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	body := "payload=attack-vector\n"
	req, _ := http.NewRequest("POST", ts.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/csv")

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}
}

// TestStreamingMiddlewareNoMatchPassThrough verifies that a stream where no
// records match any rule passes through cleanly with a 200 response.
func TestStreamingMiddlewareNoMatchPassThrough(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRule REQUEST_HEADERS:Content-Type "text/csv" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=TESTSTREAM"
			SecRule ARGS_POST "@rx malicious" "id:100,phase:2,deny,status:403"
		`).
		WithErrorCallback(errLogger(t)))
	if err != nil {
		t.Fatal(err)
	}

	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("all good"))
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	body := "key=safe1\nkey=safe2\nkey=safe3\n"
	req, _ := http.NewRequest("POST", ts.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/csv")

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	resBody, _ := io.ReadAll(res.Body)
	if string(resBody) != "all good" {
		t.Fatalf("unexpected response: %q", string(resBody))
	}
}

// TestStreamingMiddlewareWithoutContentTypeMatch verifies that when the
// Content-Type doesn't match the rule that activates the streaming processor,
// the request is processed normally (no streaming) and passes through.
func TestStreamingMiddlewareWithoutContentTypeMatch(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRule REQUEST_HEADERS:Content-Type "text/csv" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=TESTSTREAM"
			SecRule ARGS_POST "@rx malicious" "id:100,phase:2,deny,status:403"
		`).
		WithErrorCallback(errLogger(t)))
	if err != nil {
		t.Fatal(err)
	}

	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	// application/json won't match the "text/csv" rule, so TESTSTREAM won't activate
	body := `{"user":"malicious-actor"}`
	req, _ := http.NewRequest("POST", ts.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	// Should pass through — the streaming processor wasn't activated
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

// TestStreamingMiddlewareEmptyBody verifies that an empty body with the streaming
// content type doesn't cause errors.
func TestStreamingMiddlewareEmptyBody(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRule REQUEST_HEADERS:Content-Type "text/csv" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=TESTSTREAM"
			SecRule ARGS_POST "@rx malicious" "id:100,phase:2,deny,status:403"
		`).
		WithErrorCallback(errLogger(t)))
	if err != nil {
		t.Fatal(err)
	}

	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/", strings.NewReader(""))
	req.Header.Set("Content-Type", "text/csv")

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for empty body, got %d", res.StatusCode)
	}
}

// TestStreamingMiddlewareLargeStream verifies that a large stream (1000 records)
// processes correctly without errors.
func TestStreamingMiddlewareLargeStream(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRequestBodyLimit 1048576
			SecRule REQUEST_HEADERS:Content-Type "text/csv" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=TESTSTREAM"
			SecRule ARGS_POST "@rx malicious" "id:100,phase:2,deny,status:403"
		`).
		WithErrorCallback(errLogger(t)))
	if err != nil {
		t.Fatal(err)
	}

	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	var body bytes.Buffer
	for i := range 1000 {
		body.WriteString("id=")
		body.WriteString(strings.Repeat("x", 5))
		body.WriteString(",seq=")
		body.WriteString(string(rune('0' + i%10)))
		body.WriteByte('\n')
	}

	req, _ := http.NewRequest("POST", ts.URL+"/bulk", &body)
	req.Header.Set("Content-Type", "text/csv")

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

// TestStreamingMiddlewareMaliciousRecordInLargeStream verifies that a malicious
// record buried deep in a large stream still gets caught.
func TestStreamingMiddlewareMaliciousRecordInLargeStream(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRequestBodyLimit 1048576
			SecRule REQUEST_HEADERS:Content-Type "text/csv" "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=TESTSTREAM"
			SecRule ARGS_POST "@rx malicious" "id:100,phase:2,deny,status:403"
		`).
		WithErrorCallback(errLogger(t)))
	if err != nil {
		t.Fatal(err)
	}

	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ts := httptest.NewServer(handler)
	defer ts.Close()

	var body bytes.Buffer
	// 500 clean records, then 1 malicious, then 499 more
	for i := range 500 {
		body.WriteString("id=clean")
		body.WriteString(string(rune('0' + i%10)))
		body.WriteByte('\n')
	}
	body.WriteString("payload=malicious-injection\n")
	for i := range 499 {
		body.WriteString("id=also-clean")
		body.WriteString(string(rune('0' + i%10)))
		body.WriteByte('\n')
	}

	req, _ := http.NewRequest("POST", ts.URL+"/bulk", &body)
	req.Header.Set("Content-Type", "text/csv")

	res, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for malicious record at position 500, got %d", res.StatusCode)
	}
}
