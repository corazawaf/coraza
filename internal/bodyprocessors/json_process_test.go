// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

// jsonRecursionLimit is a generous nesting limit used by tests that are not
// specifically exercising the recursion guard. A limit of 0 (the zero value of
// BodyProcessorOptions) would trip the guard immediately, so a real limit is
// required, mirroring how the WAF populates it from RequestBodyJsonDepthLimit.
const jsonRecursionLimit = 3

func jsonProcessor(t *testing.T) plugintypes.BodyProcessor {
	t.Helper()
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	return bp
}

// errReader is an io.Reader that always fails, used to exercise the
// io.Copy error path in ProcessRequest and ProcessResponse.
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read failure")
}

func TestJSONProcessRequestPopulatesArgsPost(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	body := `{"a": 1, "b": "two", "c": [10, 20]}`
	if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: jsonRecursionLimit,
	}); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"json.a":   "1",
		"json.b":   "two",
		"json.c":   "2", // array length
		"json.c.0": "10",
		"json.c.1": "20",
	}
	argsPost := v.ArgsPost()
	for key, expected := range want {
		got := argsPost.Get(key)
		if len(got) == 0 {
			t.Errorf("missing ARGS_POST key %q", key)
			continue
		}
		if got[0] != expected {
			t.Errorf("ARGS_POST key %q: want %q, got %q", key, expected, got[0])
		}
	}
}

func TestJSONProcessRequestStoresRawBodyInTX(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	body := `{"user": "coraza"}`
	if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: jsonRecursionLimit,
	}); err != nil {
		t.Fatal(err)
	}

	stored := v.TX().Get("json_request_body")
	if len(stored) != 1 {
		t.Fatalf("expected json_request_body to hold a single value, got %d", len(stored))
	}
	if stored[0] != body {
		t.Errorf("json_request_body: want %q, got %q", body, stored[0])
	}
}

func TestJSONProcessRequestInvalidJSONReturnsError(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	if err := bp.ProcessRequest(strings.NewReader(`{invalid`), v, plugintypes.BodyProcessorOptions{}); err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
}

func TestJSONProcessRequestBestEffortOnInvalidJSON(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	// Valid prefix followed by garbage: the collection should still be
	// populated on a best-effort basis even though an error is returned.
	body := `{"a": 1} trailing garbage`
	err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: jsonRecursionLimit,
	})
	if err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
	if got := v.ArgsPost().Get("json.a"); len(got) == 0 || got[0] != "1" {
		t.Errorf("expected ARGS_POST json.a=1 to be populated on best effort, got %v", got)
	}
}

func TestJSONProcessRequestRecursionLimit(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	// Nesting deeper than the configured limit must be rejected.
	body := strings.Repeat(`{"a":`, 5) + "1" + strings.Repeat(`}`, 5)
	err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 3,
	})
	if err == nil {
		t.Fatal("expected a recursion limit error, got nil")
	}
	if !strings.Contains(err.Error(), "max recursion reached") {
		t.Errorf("expected max recursion error, got %v", err)
	}
}

func TestJSONProcessRequestReaderError(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := bp.ProcessRequest(errReader{}, v, plugintypes.BodyProcessorOptions{})
	if err == nil {
		t.Fatal("expected an error from the failing reader, got nil")
	}
	if err.Error() != "read failure" {
		t.Errorf("expected read failure error, got %v", err)
	}
}

func TestJSONProcessRequestEmptyObject(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	if err := bp.ProcessRequest(strings.NewReader(`{}`), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: jsonRecursionLimit,
	}); err != nil {
		t.Fatal(err)
	}
	if got := v.TX().Get("json_request_body"); len(got) != 1 || got[0] != `{}` {
		t.Errorf("expected raw empty object stored in TX, got %v", got)
	}
}

func TestJSONProcessResponsePopulatesResponseArgs(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	body := `{"a": 1, "b": "two", "c": [10, 20]}`
	if err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{}); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"json.a":   "1",
		"json.b":   "two",
		"json.c":   "2", // array length
		"json.c.0": "10",
		"json.c.1": "20",
	}
	responseArgs := v.ResponseArgs()
	for key, expected := range want {
		got := responseArgs.Get(key)
		if len(got) == 0 {
			t.Errorf("missing RESPONSE_ARGS key %q", key)
			continue
		}
		if got[0] != expected {
			t.Errorf("RESPONSE_ARGS key %q: want %q, got %q", key, expected, got[0])
		}
	}
}

func TestJSONProcessResponseStoresRawBodyInTX(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	body := `{"user": "coraza"}`
	if err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{}); err != nil {
		t.Fatal(err)
	}

	stored := v.TX().Get("json_response_body")
	if len(stored) != 1 {
		t.Fatalf("expected json_response_body to hold a single value, got %d", len(stored))
	}
	if stored[0] != body {
		t.Errorf("json_response_body: want %q, got %q", body, stored[0])
	}
}

func TestJSONProcessResponseInvalidJSONReturnsError(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	if err := bp.ProcessResponse(strings.NewReader(`{invalid`), v, plugintypes.BodyProcessorOptions{}); err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
}

func TestJSONProcessResponseBestEffortOnInvalidJSON(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	// Valid prefix followed by garbage: the collection should still be
	// populated on a best-effort basis even though an error is returned.
	body := `{"a": 1} trailing garbage`
	err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{})
	if err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
	if got := v.ResponseArgs().Get("json.a"); len(got) == 0 || got[0] != "1" {
		t.Errorf("expected RESPONSE_ARGS json.a=1 to be populated on best effort, got %v", got)
	}
}

func TestJSONProcessResponseIgnoresRecursionLimit(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	// ProcessResponse uses no recursion limit (there is no directive for the
	// response body), so deeply nested JSON must be accepted even when the
	// options carry a small limit that would trip ProcessRequest.
	body := strings.Repeat(`{"a":`, 10) + "1" + strings.Repeat(`}`, 10)
	if err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 3,
	}); err != nil {
		t.Fatalf("expected deeply nested response body to be accepted, got %v", err)
	}
}

func TestJSONProcessResponseReaderError(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	err := bp.ProcessResponse(errReader{}, v, plugintypes.BodyProcessorOptions{})
	if err == nil {
		t.Fatal("expected an error from the failing reader, got nil")
	}
	if err.Error() != "read failure" {
		t.Errorf("expected read failure error, got %v", err)
	}
}

func TestJSONProcessResponseEmptyObject(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	if err := bp.ProcessResponse(strings.NewReader(`{}`), v, plugintypes.BodyProcessorOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := v.TX().Get("json_response_body"); len(got) != 1 || got[0] != `{}` {
		t.Errorf("expected raw empty object stored in TX, got %v", got)
	}
}

var _ io.Reader = errReader{}
