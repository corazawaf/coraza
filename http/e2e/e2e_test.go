// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetHTTPSchemeIfMissing(t *testing.T) {
	tests := map[string]struct {
		rawURL      string
		expectedURL string
	}{
		"empty":         {rawURL: "", expectedURL: ""},
		"path":          {rawURL: "abc", expectedURL: "http://abc"},
		"path and port": {rawURL: "abc:123", expectedURL: "http://abc:123"},
		"no schema":     {rawURL: "://localhost:123/", expectedURL: "://localhost:123/"},
		"with schema":   {rawURL: "http://1.2.3.4:8080/abc", expectedURL: "http://1.2.3.4:8080/abc"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			url := setHTTPSchemeIfMissing(test.rawURL)
			if want, have := test.expectedURL, url; want != have {
				t.Errorf("unexpected URL, want %q, have %q", want, have)
			}
		})
	}
}

func Test_expectStatusCode(t *testing.T) {
	ok := expectStatusCode(http.StatusOK)
	if err := ok(http.StatusOK); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := ok(http.StatusForbidden); err == nil {
		t.Fatalf("expected an error when status code mismatches")
	}
}

func Test_expectNulledBodyStatusCode(t *testing.T) {
	// nulledBody=true → expect expectedNulledBodyCode
	nulled := expectNulledBodyStatusCode(true, 403, 200)
	if err := nulled(200); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := nulled(403); err == nil {
		t.Fatalf("expected error when nulledBody=true and code != expectedNulledBodyCode")
	}

	// nulledBody=false → expect expectedEmptyBodyCode
	nonNulled := expectNulledBodyStatusCode(false, 403, 200)
	if err := nonNulled(403); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := nonNulled(200); err == nil {
		t.Fatalf("expected error when nulledBody=false and code != expectedEmptyBodyCode")
	}
}

func Test_expectEmptyOrNulledBody(t *testing.T) {
	// nulled body: non-empty, all zeros
	zeros := make([]byte, 8)
	if err := expectEmptyOrNulledBody(true)(len(zeros), zeros); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// failures for nulled body case
	if err := expectEmptyOrNulledBody(true)(0, nil); err == nil {
		t.Fatalf("expected error (content-length 0)")
	}
	if err := expectEmptyOrNulledBody(true)(0, []byte{}); err == nil {
		t.Fatalf("expected error (empty body)")
	}
	nonZero := append([]byte{0, 0, 0}, byte('x'))
	if err := expectEmptyOrNulledBody(true)(len(nonZero), nonZero); err == nil {
		t.Fatalf("expected error (non-zero byte present)")
	}

	// empty body case
	if err := expectEmptyOrNulledBody(false)(0, nil); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := expectEmptyOrNulledBody(false)(0, []byte{}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := expectEmptyOrNulledBody(false)(1, []byte{'a'}); err == nil {
		t.Fatalf("expected error (non-empty)")
	}
}

func Test_expectEmptyBody(t *testing.T) {
	if err := expectEmptyBody()(0, nil); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := expectEmptyBody()(0, []byte{}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := expectEmptyBody()(1, []byte{'a'}); err == nil {
		t.Fatalf("expected error (non-empty)")
	}
}

func Test_VerifySSEStreamResponse_wrongContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "event: message\n\n")
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if err := VerifySSEStreamResponse(resp, 1, 1*time.Second, 1*time.Second); err == nil {
		t.Fatalf("expected error for wrong content type")
	}
}
