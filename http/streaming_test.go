// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package http

import (
	"context"
	"io"
	"net"
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

// Test that with SecRuleEngine On and with response body access enabled,
// when SecResponseBodyMimeType doesn't match, the finalized Flush should
// still reach the client immediately.
func TestStreamingEngineOnResponseBodyMimeType(t *testing.T) {
	directives := strings.TrimSpace(`
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType application/json`)

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
		t.Fatalf("Flush() was propagated to the underlying response writer despite headers being blocked")
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

// TestStreamingEngineOnNoResponseBodyAccess_HTTP10 verifies that when SecRuleEngine is On but
// SecResponseBodyAccess is Off, the WAF does not block or delay Flush() calls during
// streaming HTTP/1.0 responses. It uses a raw TCP connection to simulate an HTTP/1.0
// client and checks that response chunks are sent immediately as expected.
// This validates that streaming responses work correctly without response body buffering
// interfering, even in environments that do not support HTTP/1.1 chunked transfer encoding.
//
// We cannot use httptest.Server here because it always uses HTTP/1.1 internally,
// even if the client request is HTTP/1.0. Since this test specifically targets
// HTTP/1.0 behavior, we must bypass httptest and use a net.Listener with a custom http.Server
// to ensure the response is sent using HTTP/1.0 semantics.
func TestStreamingEngineOnNoResponseBodyAccess_HTTP10(t *testing.T) {
	directives := strings.TrimSpace(`
SecRuleEngine On
SecResponseBodyAccess Off`)

	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
	if err != nil {
		t.Fatalf("failed to create WAF: %v", err)
	}

	// Create a listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	// Base address for the server
	address := listener.Addr().String()

	// Set up HTTP server with handler
	server := &http.Server{
		Handler: WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Hello "))
			flusher.Flush()
			time.Sleep(500 * time.Millisecond)
			_, _ = w.Write([]byte("world!"))
		})),
	}

	// Run server in a goroutine
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect client
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Send HTTP/1.0 GET request
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))

	// Read initial response
	// It's crucial to set a timeout shorter than the delay in the server's handler
	err = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if err != nil {
		t.Fatalf("failed to set read timeout: %v", err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	responseText := string(buf[:n])
	// Verify HTTP/1.0 response
	if !strings.HasPrefix(responseText, "HTTP/1.0 200") {
		t.Fatalf("expected HTTP/1.0 200 OK, got: %q", responseText)
	}

	// Check that the first part "Hello " is sent immediately
	if !strings.Contains(responseText, "Hello ") {
		t.Fatalf("response does not contain 'Hello ': %q", responseText)
	}

	// Wait for the server to send the second part
	time.Sleep(600 * time.Millisecond)
	// Reset timeout for the second read
	err = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if err != nil {
		t.Fatalf("failed to set read timeout: %v", err)
	}
	n, err = conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("error reading second part: %v", err)
	}

	// Check the second part
	if n > 0 && !strings.Contains(string(buf[:n]), "world!") {
		t.Fatalf("second part does not contain 'world!': %q", string(buf[:n]))
	}

	// Stop the server
	server.Close()
}
