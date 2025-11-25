// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
)

// We use a spy to verify Flush() is actually called on the underlying writer.
// Relying solely on network finalized timing can be flaky in unit tests (httptest).
// spy.flushed: Proves that the Coraza middleware correctly propagated the signal.
type flushSpy struct {
	http.ResponseWriter
	flushed bool
}

func (f *flushSpy) Flush() {
	f.flushed = true
	if fl, ok := f.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// readFirstN: Proves that the client actually received the bytes (end-to-end verification).
// readFirstN tries to read exactly n bytes within the given timeout.
// It returns the bytes read (possibly less than n) and whether the deadline was met.
func readFirstN(t *testing.T, r io.Reader, n int, timeout time.Duration) ([]byte, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resultC := make(chan []byte, 1)
	errC := make(chan error, 1)
	go func() {
		buf := make([]byte, n)
		read := 0
		for read < n {
			m, err := r.Read(buf[read:])
			if err != nil {
				if err == io.EOF {
					break
				}
				errC <- err
				return
			}
			read += m
		}
		resultC <- buf[:read]
	}()

	select {
	case b := <-resultC:
		return b, true
	case err := <-errC:
		t.Fatalf("unexpected read error: %v", err)
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

// Test that with SecRuleEngine Off, the middleware does not wrap/alter the ResponseWriter
// and Flush reaches the client immediately, enabling finalized responses.
func TestStreamingEngineOff(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`SecRuleEngine Off`))
	if err != nil {
		t.Fatalf("failed to create WAF: %v", err)
	}

	var spy *flushSpy
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spy = &flushSpy{ResponseWriter: w}
		handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Hello "))
			flusher.Flush()
			time.Sleep(500 * time.Millisecond)
			_, _ = w.Write([]byte("world!"))
		}))
		handler.ServeHTTP(spy, r)
	}))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error performing request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", res.StatusCode)
	}

	// Expect to receive the first chunk promptly after Flush.
	// Since 200ms < 500ms (server sleep), success means we got data BEFORE sleep ended.
	b, ok := readFirstN(t, res.Body, len("Hello "), 200*time.Millisecond)
	if !ok {
		t.Fatalf("did not receive first chunk in time; flush likely did not propagate")
	}
	if string(b) != "Hello " {
		t.Fatalf("unexpected first chunk: %q", string(b))
	}
	// Verify Flush was actually propagated
	if spy == nil || !spy.flushed {
		t.Fatalf("Flush() was not propagated to the underlying response writer")
	}
	// Read the remainder of the body without timing assertions.
	rest, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed reading remaining body: %v", err)
	}
	if string(rest) != "world!" {
		t.Fatalf("unexpected remaining body: %q", string(rest))
	}
}

// Test that with SecRuleEngine On but without response body access enabled,
// finalized Flush should still reach the client immediately.
func TestStreamingEngineOnNoResponseBodyAccess(t *testing.T) {
	directives := strings.TrimSpace(`
SecRuleEngine On
SecResponseBodyAccess Off`)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("failed to create WAF: %v", err)
	}

	var spy *flushSpy
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spy = &flushSpy{ResponseWriter: w}
		handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Hello "))
			flusher.Flush()
			time.Sleep(500 * time.Millisecond)
			_, _ = w.Write([]byte("world!"))
		}))
		handler.ServeHTTP(spy, r)
	}))
	defer ts.Close()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error performing request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", res.StatusCode)
	}

	// We expect to receive the first chunk promptly after Flush.
	// Since 200ms < 500ms (server sleep), success means we got data BEFORE sleep ended.
	b, ok := readFirstN(t, res.Body, len("Hello "), 200*time.Millisecond)
	if !ok {
		// This is the current buggy behavior: flush is swallowed by the interceptor.
		t.Fatalf("did not receive first chunk in time; finalized is hindered when SecRuleEngine is On")
	}
	if string(b) != "Hello " {
		t.Fatalf("unexpected first chunk: %q", string(b))
	}

	// Verify Flush was actually propagated
	if spy == nil || !spy.flushed {
		t.Fatalf("Flush() was not propagated to the underlying response writer")
	}

	// Read the remainder of the body without timing assertions.
	rest, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed reading remaining body: %v", err)
	}
	if string(rest) != "world!" {
		t.Fatalf("unexpected remaining body: %q", string(rest))
	}
}

// Test that with SecRuleEngine On and without response body access enabled,
// when a response is blocked in phase3 (headers) the flush is not propagated.
func TestStreamingEngineOnNoResponseBodyAccessShouldStillCheckHeaders(t *testing.T) {
	directives := strings.TrimSpace(`
SecRuleEngine On
SecRule RESPONSE_HEADERS:trigger "@streq trigger" "id:1,phase:3,t:lowercase,deny"
SecResponseBodyAccess Off`)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("failed to create WAF: %v", err)
	}

	var spy *flushSpy
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spy = &flushSpy{ResponseWriter: w}
		handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			// set the trigger header
			w.Header().Set("trigger", "trigger")
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Hello "))
			flusher.Flush()
			time.Sleep(500 * time.Millisecond)
			_, _ = w.Write([]byte("world!"))
		}))
		handler.ServeHTTP(spy, r)
	}))
	defer ts.Close()

	res, err := http.Get(ts.URL)

	if err != nil {
		t.Fatalf("unexpected error performing request: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected status code: %d", res.StatusCode)
	}

	// Ensure Flush was NOT propagated
	if spy != nil && spy.flushed {
		t.Fatalf("Flush() was propagated to the underlying response writer besides headers being blocked")
	}

	// Read the remainder of the body without timing assertions.
	rest, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("failed reading remaining body: %v", err)
	}
	if string(rest) != "" {
		t.Fatalf("unexpected remaining body: %q", string(rest))
	}
}
