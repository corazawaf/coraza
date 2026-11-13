// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"strconv"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

// These tests document the current behaviour of RESPONSE_CONTENT_LENGTH, for
// the questions raised in issue #1566. They are descriptive: each one asserts
// what the code does today, so a future change to any of it is a visible test
// change rather than a silent behaviour shift.

// newResponseTx returns a transaction with response body access on and the
// given content type allowed, ready for ProcessResponseBody.
func newResponseTx(t *testing.T, contentType string, mimes []string) *Transaction {
	t.Helper()
	waf := NewWAF()
	waf.ResponseBodyAccess = true
	waf.ResponseBodyMimeTypes = mimes
	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("process request body: %v", err)
	}
	tx.AddResponseHeader("content-type", contentType)
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	return tx
}

func writeResponse(t *testing.T, tx *Transaction, body string) {
	t.Helper()
	if _, _, err := tx.WriteResponseBody([]byte(body)); err != nil {
		t.Fatalf("write response body: %v", err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatalf("process response body: %v", err)
	}
}

// Q2: when is RESPONSE_CONTENT_LENGTH populated?
func TestResponseContentLengthSetWithoutBodyProcessor(t *testing.T) {
	tx := newResponseTx(t, "text/plain", []string{"text/plain"})
	defer tx.Close()

	body := "the response body"
	writeResponse(t, tx, body)

	got := tx.variables.responseContentLength.Get()
	if want := strconv.Itoa(len(body)); got != want {
		t.Errorf("RESPONSE_CONTENT_LENGTH = %q, want %q", got, want)
	}
	// It is computed from the buffer, not from a content-length header: no
	// such header was ever set on this transaction.
	if tx.variables.responseBody.Get() != body {
		t.Errorf("RESPONSE_BODY = %q, want %q", tx.variables.responseBody.Get(), body)
	}
}

// Q2, continued: with a response body processor active, the variable is left
// at its zero value, because only the else branch of ProcessResponseBody
// computes it. RESPONSE_BODY is not set either, so the two stay consistent.
func TestResponseContentLengthNotSetWithBodyProcessor(t *testing.T) {
	tx := newResponseTx(t, "application/json", []string{"application/json"})
	defer tx.Close()

	tx.variables.resBodyProcessor.Set("JSON")
	writeResponse(t, tx, `{"a":"b"}`)

	if got := tx.variables.responseContentLength.Get(); got != "" {
		t.Errorf("RESPONSE_CONTENT_LENGTH = %q, want it left unset with a body processor", got)
	}
	if got := tx.variables.responseBody.Get(); got != "" {
		t.Errorf("RESPONSE_BODY = %q, want it left unset with a body processor", got)
	}
}

// A body that is not processable leaves the variable unset: ProcessResponseBody
// returns before reading the buffer at all.
func TestResponseContentLengthNotSetWhenBodyNotProcessable(t *testing.T) {
	tx := newResponseTx(t, "image/png", []string{"text/plain"})
	defer tx.Close()

	writeResponse(t, tx, "\x89PNG not text")

	if got := tx.variables.responseContentLength.Get(); got != "" {
		t.Errorf("RESPONSE_CONTENT_LENGTH = %q, want it unset for an unprocessable body", got)
	}
}

// Q3: does ctl:forceResponseBodyVariable affect RESPONSE_CONTENT_LENGTH?
// Yes, indirectly. It makes IsResponseBodyProcessable return true for a MIME
// type that is not in SecResponseBodyMimeType, so ProcessResponseBody reaches
// the branch that computes the length instead of returning early.
func TestForceResponseBodyVariableMakesContentLengthAvailable(t *testing.T) {
	tx := newResponseTx(t, "image/png", []string{"text/plain"})
	defer tx.Close()

	if tx.IsResponseBodyProcessable() {
		t.Fatal("image/png should not be processable without the ctl")
	}
	tx.ForceResponseBodyVariable = true
	if !tx.IsResponseBodyProcessable() {
		t.Fatal("ForceResponseBodyVariable should make any MIME type processable")
	}

	body := "forced body"
	writeResponse(t, tx, body)

	got := tx.variables.responseContentLength.Get()
	if want := strconv.Itoa(len(body)); got != want {
		t.Errorf("RESPONSE_CONTENT_LENGTH = %q, want %q with forceResponseBodyVariable", got, want)
	}
}

// Q1: the naming asymmetry with REQUEST_BODY_LENGTH is visible in their
// defaults. REQUEST_BODY_LENGTH is initialised to "0" when a transaction
// starts, so a rule reading it always sees a number; RESPONSE_CONTENT_LENGTH
// starts empty, so the same rule shape on the response side sees "".
func TestRequestBodyLengthAndResponseContentLengthDefaultsDiffer(t *testing.T) {
	waf := NewWAF()
	tx := waf.NewTransaction()
	defer tx.Close()

	if got := tx.variables.requestBodyLength.Get(); got != "0" {
		t.Errorf("REQUEST_BODY_LENGTH default = %q, want %q", got, "0")
	}
	if got := tx.variables.responseContentLength.Get(); got != "" {
		t.Errorf("RESPONSE_CONTENT_LENGTH default = %q, want it empty", got)
	}
}

// RESPONSE_CONTENT_LENGTH is a phase 4 variable: it is not available while
// phase 3 (response headers) rules run, since the body has not been read yet.
func TestResponseContentLengthUnsetDuringResponseHeadersPhase(t *testing.T) {
	tx := newResponseTx(t, "text/plain", []string{"text/plain"})
	defer tx.Close()

	if got := tx.variables.responseContentLength.Get(); got != "" {
		t.Errorf("RESPONSE_CONTENT_LENGTH = %q after ProcessResponseHeaders, want it empty", got)
	}
	if tx.LastPhase() != types.PhaseResponseHeaders {
		t.Fatalf("LastPhase = %v, want %v", tx.LastPhase(), types.PhaseResponseHeaders)
	}
}
