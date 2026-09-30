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
// required, mirroring how the WAF populates it from RequestBodyJsonDepthLimit
// and ResponseBodyJsonDepthLimit.
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

// TestJSONProcessRequestKeyCollisionDoesNotHideNestedValue is the
// ARGS_POST-level regression for GHSA-5gj4-9gm7-2fx2: two JSON properties
// that flatten to the same ARGS_POST key used to leave only one value, so a
// harmless property could hide an attacker-controlled one from every rule,
// while a standard JSON parser still exposed both to the backend. Every value
// must now be present.
func TestJSONProcessRequestKeyCollisionDoesNotHideNestedValue(t *testing.T) {
	tests := []struct {
		name string
		body string
		// keys are read and their values unioned, so a row holds whether or
		// not the keys fold to one bucket (see case_sensitive_args_keys).
		keys []string
		want []string
		// ordered asserts want in document order on a single key; otherwise
		// the values are compared as a set.
		ordered bool
	}{
		{
			// A literal dot in a property name flattens to the same key as a
			// nested path, and the later top-level value used to overwrite
			// the earlier nested one.
			name:    "dotted property name",
			body:    `{"account":{"role":"1' OR '1'='1"},"account.role":"safe"}`,
			keys:    []string{"json.account.role"},
			want:    []string{"1' OR '1'='1", "safe"},
			ordered: true,
		},
		{
			// Keys differing only by case are distinct in readJSON's map but
			// fold to one bucket in the case-insensitive ARGS_POST, where
			// SetIndex let whichever key map iteration visited last
			// overwrite the other. Add always appends.
			name: "case-variant property name",
			body: `{"account":{"role":"1' OR '1'='1","Role":"safe"}}`,
			keys: []string{"json.account.role", "json.account.Role"},
			want: []string{"1' OR '1'='1", "safe"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bp := jsonProcessor(t)
			v := corazawaf.NewTransactionVariables()
			if err := bp.ProcessRequest(strings.NewReader(tt.body), v, plugintypes.BodyProcessorOptions{
				RequestBodyRecursionLimit: jsonRecursionLimit,
			}); err != nil {
				t.Fatal(err)
			}

			if tt.ordered {
				got := v.ArgsPost().Get(tt.keys[0])
				if len(got) != len(tt.want) {
					t.Fatalf("ARGS_POST %s = %v, want %v", tt.keys[0], got, tt.want)
				}
				for i := range tt.want {
					if got[i] != tt.want[i] {
						t.Errorf("ARGS_POST %s[%d] = %q, want %q", tt.keys[0], i, got[i], tt.want[i])
					}
				}
				return
			}

			got := map[string]bool{}
			for _, k := range tt.keys {
				for _, val := range v.ArgsPost().Get(k) {
					got[val] = true
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ARGS_POST %v = %v, want (any order) %v", tt.keys, got, tt.want)
			}
			for _, w := range tt.want {
				if !got[w] {
					t.Errorf("ARGS_POST %v missing %q, got %v", tt.keys, w, got)
				}
			}
		})
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
	if err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: jsonRecursionLimit,
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
	if err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: jsonRecursionLimit,
	}); err != nil {
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
	err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: jsonRecursionLimit,
	})
	if err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
	if got := v.ResponseArgs().Get("json.a"); len(got) == 0 || got[0] != "1" {
		t.Errorf("expected RESPONSE_ARGS json.a=1 to be populated on best effort, got %v", got)
	}
}

func TestJSONProcessResponseRecursionLimit(t *testing.T) {
	bp := jsonProcessor(t)
	v := corazawaf.NewTransactionVariables()

	// Nesting deeper than the configured limit must be rejected. Regression
	// test for GHSA-3c6w-j9xm-8h2h: ProcessResponse used to ignore any
	// recursion limit (there was no directive for the response body), so a
	// deeply nested response body was processed in full regardless of depth.
	body := strings.Repeat(`{"a":`, 5) + "1" + strings.Repeat(`}`, 5)
	err := bp.ProcessResponse(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: 3,
	})
	if err == nil {
		t.Fatal("expected a recursion limit error, got nil")
	}
	if !strings.Contains(err.Error(), "max recursion reached") {
		t.Errorf("expected max recursion error, got %v", err)
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

	if err := bp.ProcessResponse(strings.NewReader(`{}`), v, plugintypes.BodyProcessorOptions{
		ResponseBodyRecursionLimit: jsonRecursionLimit,
	}); err != nil {
		t.Fatal(err)
	}
	if got := v.TX().Get("json_response_body"); len(got) != 1 || got[0] != `{}` {
		t.Errorf("expected raw empty object stored in TX, got %v", got)
	}
}

var _ io.Reader = errReader{}
