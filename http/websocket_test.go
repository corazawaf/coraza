// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package http

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
)

// wsUpgradeViaWriteHeader is a WebSocket echo handler that follows the standard
// library upgrade pattern used by most WebSocket frameworks:
//  1. Set upgrade headers on the ResponseWriter.
//  2. Call w.WriteHeader(101) — the Coraza interceptor must flush this immediately.
//  3. Call Hijack() to take over the raw connection.
//  4. Echo one frame back to the client.
//
// This flow exercises the "immediate 101 flush" path in rwInterceptor.WriteHeader,
// which is distinct from the path tested by TestWAFNotBypassedAfterWebSocketUpgrade
// (which calls Hijack() directly and writes the 101 response line manually).
func wsUpgradeViaWriteHeader(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Verify hijacking support before sending 101: sending the upgrade response
	// and then failing to hijack would leave the client stuck until its deadline.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server does not support connection hijacking", http.StatusInternalServerError)
		return
	}

	// Standard upgrade sequence: set headers, then flush 101 via ResponseWriter.
	// The Coraza interceptor must flush the 101 immediately at this point.
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", wsComputeAccept(key))
	w.WriteHeader(http.StatusSwitchingProtocols)

	conn, brw, err := hijacker.Hijack()
	if err != nil {
		// 101 already sent; nothing useful can be written to the client now.
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	wsEchoOneFrame(conn, brw)
}

// doRawWSUpgrade sends a WebSocket upgrade request over conn and returns a
// bufio.Reader positioned immediately after the response headers.
func doRawWSUpgrade(t *testing.T, conn net.Conn, addr, key string, extraHeaders map[string]string) (*bufio.Reader, int) {
	t.Helper()

	var sb strings.Builder
	fmt.Fprintf(&sb, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", addr, key)
	for k, v := range extraHeaders {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(&sb, "\r\n")

	if _, err := fmt.Fprint(conn, sb.String()); err != nil {
		t.Fatalf("writing upgrade request: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading status line: %v", err)
	}

	parts := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(parts) < 2 {
		t.Fatalf("malformed status line: %q", statusLine)
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("parsing status code from %q: %v", statusLine, err)
	}

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading response headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	return br, statusCode
}

// TestWebSocketUpgradeViaResponseWriter verifies that the full WebSocket upgrade
// flow works when the server uses w.WriteHeader(101) before Hijack(), which is
// the pattern used by most WebSocket libraries (e.g. gorilla/websocket,
// nhooyr.io/websocket). This exercises the "immediate 101 flush" path in the
// Coraza interceptor rather than the manual-header-write path tested by
// TestWAFNotBypassedAfterWebSocketUpgrade.
func TestWebSocketUpgradeViaResponseWriter(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType application/json
`))
	if err != nil {
		t.Fatalf("creating WAF: %v", err)
	}

	ts := httptest.NewServer(WrapHandler(waf, http.HandlerFunc(wsUpgradeViaWriteHeader)))
	t.Cleanup(ts.Close)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dialing test server: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	br, statusCode := doRawWSUpgrade(t, conn, ts.Listener.Addr().String(), key, nil)

	if statusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 Switching Protocols, got %d", statusCode)
	}

	// Send a masked WebSocket text frame and verify the echo.
	const msg = "hello coraza"
	if _, err := conn.Write(wsBuildMaskedFrame([]byte(msg))); err != nil {
		t.Fatalf("writing WebSocket frame: %v", err)
	}

	echo, err := wsReadFrame(br)
	if err != nil {
		t.Fatalf("reading WebSocket echo: %v", err)
	}
	if !bytes.Equal(echo, []byte(msg)) {
		t.Fatalf("echo mismatch: want %q, got %q", msg, echo)
	}
}

// TestWebSocketUpgradeBlockedByWAF verifies that a WebSocket upgrade request
// is blocked by the WAF when the request matches a deny rule, and that the
// client receives a 403 Forbidden instead of a 101 Switching Protocols.
func TestWebSocketUpgradeBlockedByWAF(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRule REQUEST_HEADERS:X-Attack "@streq malicious" "id:1,phase:1,deny,status:403"
`))
	if err != nil {
		t.Fatalf("creating WAF: %v", err)
	}

	ts := httptest.NewServer(WrapHandler(waf, http.HandlerFunc(wsUpgradeViaWriteHeader)))
	t.Cleanup(ts.Close)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dialing test server: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	_, statusCode := doRawWSUpgrade(t, conn, ts.Listener.Addr().String(), key, map[string]string{
		"X-Attack": "malicious",
	})

	if statusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for malicious upgrade, got %d", statusCode)
	}
}
