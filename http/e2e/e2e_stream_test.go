// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// makeTestResponse builds an http.Response with given body and headers
func makeTestResponse(body io.ReadCloser, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: 200, Header: h, Body: body}
}

// sseStreamPipe produces an SSE stream with configurable timing.
// It writes events in the format:
// event: message
// data: <index>
//
// (blank line separates events)
func sseStreamPipe(eventCount int, firstDelay, interEventDelay time.Duration) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()

		if firstDelay > 0 {
			time.Sleep(firstDelay)
		}

		for i := range eventCount {
			fmt.Fprintf(pw, "event: message\n")
			fmt.Fprintf(pw, "data: %d\n\n", i)

			if i < eventCount-1 && interEventDelay > 0 {
				time.Sleep(interEventDelay)
			}
		}
	}()
	return pr
}

// noEventPipe writes non-event SSE data periodically (like heartbeats or comments)
func noEventPipe(interval time.Duration) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer pw.Close()

		for range ticker.C {
			fmt.Fprintf(pw, ": heartbeat\n\n")
		}
	}()
	return pr
}

// errorReader simulates a read error after emitting one line
type errorReader struct {
	returned bool
}

func (e *errorReader) Read(p []byte) (int, error) {
	if !e.returned {
		e.returned = true
		data := []byte("event: test\n")
		copy(p, data)
		return len(data), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func (e *errorReader) Close() error { return nil }

func TestVerifySSEStreamResponse_InvalidContentType(t *testing.T) {
	resp := makeTestResponse(
		http.NoBody,
		map[string]string{"Content-Type": "application/json"},
	)

	err := verifySSEStreamResponse(resp, 1, 100*time.Millisecond, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "text/event-stream") {
		t.Fatalf("expected Content-Type error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_ContentLengthPresent(t *testing.T) {
	resp := makeTestResponse(
		http.NoBody,
		map[string]string{
			"Content-Type":   "text/event-stream",
			"Content-Length": "100",
		},
	)

	err := verifySSEStreamResponse(resp, 1, 100*time.Millisecond, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "Content-Length") {
		t.Fatalf("expected Content-Length error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_NegativeTotalDeadline(t *testing.T) {
	resp := makeTestResponse(
		http.NoBody,
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 1, 100*time.Millisecond, -100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "totalDeadline") {
		t.Fatalf("expected totalDeadline negative error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_ZeroTotalDeadline(t *testing.T) {
	resp := makeTestResponse(
		http.NoBody,
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 1, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "totalDeadline") {
		t.Fatalf("expected totalDeadline zero error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_NegativeFirstChunkDeadline(t *testing.T) {
	resp := makeTestResponse(
		http.NoBody,
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 1, -100*time.Millisecond, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "firstChunkDeadline") {
		t.Fatalf("expected firstChunkDeadline negative error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_TotalDeadlineTooSmall(t *testing.T) {
	resp := makeTestResponse(
		http.NoBody,
		map[string]string{"Content-Type": "text/event-stream"},
	)

	// totalDeadline <= firstChunkDeadline
	err := verifySSEStreamResponse(resp, 1, 500*time.Millisecond, 400*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "greater than") {
		t.Fatalf("expected totalDeadline > firstChunkDeadline error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_ReadError(t *testing.T) {
	resp := makeTestResponse(
		&errorReader{},
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 1, 100*time.Millisecond, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "read error") {
		t.Fatalf("expected read error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_FirstChunkTooLate(t *testing.T) {
	// First event arrives after 150ms, but firstChunkDeadline is 100ms
	resp := makeTestResponse(
		sseStreamPipe(1, 150*time.Millisecond, 0),
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 1, 100*time.Millisecond, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "first body chunk too late") {
		t.Fatalf("expected first chunk too late error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_NoEvents(t *testing.T) {
	// Stream closes immediately without any events
	pr, pw := io.Pipe()
	pw.Close()

	resp := makeTestResponse(
		pr,
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 1, 100*time.Millisecond, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "no event received") {
		t.Fatalf("expected no event received error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_EventCountMismatch(t *testing.T) {
	// Stream produces 2 events but we expect 3
	resp := makeTestResponse(
		sseStreamPipe(2, 10*time.Millisecond, 10*time.Millisecond),
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 3, 50*time.Millisecond, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "expected 3 events, got 2") {
		t.Fatalf("expected event count mismatch error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_StreamEndedTooQuickly(t *testing.T) {
	// All events arrive very quickly (within firstChunkDeadline)
	// This indicates the response was buffered, not streamed
	resp := makeTestResponse(
		sseStreamPipe(3, 5*time.Millisecond, 2*time.Millisecond),
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 3, 100*time.Millisecond, 500*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "ended too quickly") {
		t.Fatalf("expected ended too quickly error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_TotalDeadlineExceeded(t *testing.T) {
	// Stream keeps sending data but never completes the expected event count
	resp := makeTestResponse(
		noEventPipe(10*time.Millisecond),
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 5, 50*time.Millisecond, 150*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not complete within total deadline") {
		t.Fatalf("expected total deadline exceeded error, got: %v", err)
	}
}

func TestVerifySSEStreamResponse_Success(t *testing.T) {
	// Proper streaming: first event arrives quickly (10ms < 50ms)
	// Events are spaced out (30ms each) so total time ~130ms > 50ms firstChunkDeadline
	// All 5 events arrive within 1 second
	resp := makeTestResponse(
		sseStreamPipe(5, 10*time.Millisecond, 30*time.Millisecond),
		map[string]string{"Content-Type": "text/event-stream"},
	)

	err := verifySSEStreamResponse(resp, 5, 50*time.Millisecond, 1*time.Second)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestVerifySSEStreamResponse_SuccessWithVariousHeaders(t *testing.T) {
	// Test that Content-Type matching is case-insensitive and flexible
	// Need sufficient delay so total time exceeds firstChunkDeadline
	resp := makeTestResponse(
		sseStreamPipe(3, 10*time.Millisecond, 40*time.Millisecond),
		map[string]string{"Content-Type": "TEXT/EVENT-STREAM; charset=utf-8"},
	)

	err := verifySSEStreamResponse(resp, 3, 50*time.Millisecond, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("expected success with varied content-type, got error: %v", err)
	}
}
