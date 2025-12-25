// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

func Test_VerifySSEStreamResponse_ok(t *testing.T) {
	// SSE test server that streams 3 events with small delays and no Content-Length
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		if f, ok := w.(http.Flusher); ok {
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "event: message\n")
				fmt.Fprintf(w, "data: %d\n\n", i)
				f.Flush()
				time.Sleep(50 * time.Millisecond)
			}
		}
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if err := VerifySSEStreamResponse(resp, 3, 10*time.Millisecond, 2*time.Second); err != nil {
		t.Fatalf("VerifySSEStreamResponse failed: %v", err)
	}
}

func Test_runHealthChecks(t *testing.T) {
	// The function polls once per second; keep test count small to avoid long runtime.
	// Server returns 200 for any path; but for the "config check" path we want 424.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "config") {
			w.WriteHeader(424)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	healthChecks := []healthCheck{
		{name: "health", url: ts.URL + "/status", expectedCode: 200},
		{name: "proxy", url: ts.URL + "/proxy", expectedCode: 200},
		{name: "config", url: ts.URL + "/config", expectedCode: 424},
	}
	if err := runHealthChecks(healthChecks); err != nil {
		t.Fatalf("runHealthChecks failed: %v", err)
	}
}

func Test_runTests(t *testing.T) {
	// Server that returns depending on URL/method/body
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "OK")
		case "/nulled":
			// Return a nulled (all-zero) body of length 4
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte{0, 0, 0, 0})
			if err != nil {
				t.Fatalf("unexpected error while writing nulled body: %v", err)
			}
		case "/sse":
			// Stream 2 events
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				fmt.Fprint(w, "event: message\n")
				fmt.Fprint(w, "data: 1\n\n")
				f.Flush()
				time.Sleep(30 * time.Millisecond)
				fmt.Fprint(w, "event: message\n")
				fmt.Fprint(w, "data: 2\n\n")
				f.Flush()
			} else {
				fmt.Fprint(w, "event: message\n\n")
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	tests := []testCase{
		{
			name:               "basic 200",
			requestURL:         ts.URL + "/ok",
			requestMethod:      http.MethodGet,
			expectedStatusCode: expectStatusCode(200),
		},
		{
			name:               "nulled body path",
			requestURL:         ts.URL + "/nulled",
			requestMethod:      http.MethodGet,
			expectedStatusCode: expectStatusCode(200),
			expectedBody:       expectEmptyOrNulledBody(true),
		},
		{
			name:               "sse stream",
			requestURL:         ts.URL + "/sse",
			requestMethod:      http.MethodGet,
			expectedStatusCode: expectStatusCode(200),
			streamCheck: func(resp *http.Response) error {
				return VerifySSEStreamResponse(resp, 2, 10*time.Millisecond, 1*time.Second)
			},
		},
	}
	if err := runTests(tests); err != nil {
		t.Fatalf("runTests failed: %v", err)
	}
}
