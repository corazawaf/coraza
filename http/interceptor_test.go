// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo

package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestWriteHeader(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()
	rw, responseProcessor := wrap(res, req, tx)
	rw.WriteHeader(204)
	rw.WriteHeader(205)
	// although we called WriteHeader, status code should be applied until
	// responseProcessor is called.
	if unwanted, have := 204, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// although we called a second time with 205, status code should remain the first
	// value.
	if want, have := 204, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

func TestWrite(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()

	rw, responseProcessor := wrap(res, req, tx)
	_, err = rw.Write([]byte("hello"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = rw.Write([]byte("world"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 200, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

func TestWriteWithWriteHeader(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()

	rw, responseProcessor := wrap(res, req, tx)
	rw.WriteHeader(201)
	// although we called WriteHeader, status code should be applied until
	// responseProcessor is called.
	if unwanted, have := 201, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	_, err = rw.Write([]byte("hello"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = rw.Write([]byte("world"))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 201, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

func TestFlush(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("WriteHeader before Flush", func(t *testing.T) {
		tx := waf.NewTransaction()
		req, _ := http.NewRequest("GET", "", nil)
		res := httptest.NewRecorder()
		rw, responseProcessor := wrap(res, req, tx)
		rw.WriteHeader(204)
		rw.(http.Flusher).Flush()
		// although we called WriteHeader, status code should be applied until
		// responseProcessor is called.
		if unwanted, have := 204, res.Code; unwanted == have {
			t.Errorf("unexpected status code %d", have)
		}

		err = responseProcessor(tx, req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if want, have := 204, res.Code; want != have {
			t.Errorf("unexpected status code, want %d, have %d", want, have)
		}
	})

	t.Run("Flush before WriteHeader", func(t *testing.T) {
		tx := waf.NewTransaction()
		req, _ := http.NewRequest("GET", "", nil)
		res := httptest.NewRecorder()
		rw, responseProcessor := wrap(res, req, tx)
		rw.(http.Flusher).Flush()
		rw.WriteHeader(204)

		if want, have := 200, res.Code; want != have {
			t.Errorf("unexpected status code, want %d, have %d", want, have)
		}

		err = responseProcessor(tx, req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if want, have := 200, res.Code; want != have {
			t.Errorf("unexpected status code, want %d, have %d", want, have)
		}
	})
}

type testReaderFrom struct {
	io.Writer
}

func (x *testReaderFrom) ReadFrom(r io.Reader) (n int64, err error) {
	return io.Copy(x, r)
}

func TestReadFrom(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()

	type responseWriter interface {
		http.ResponseWriter
		http.Flusher
	}

	resWithReaderFrom := struct {
		responseWriter
		io.ReaderFrom
	}{
		res,
		&testReaderFrom{res},
	}

	rw, responseProcessor := wrap(resWithReaderFrom, req, tx)
	rw.WriteHeader(201)
	// although we called WriteHeader, status code should be applied until
	// responseProcessor is called.
	if unwanted, have := 201, res.Code; unwanted == have {
		t.Errorf("unexpected status code %d", have)
	}

	_, err = rw.(io.ReaderFrom).ReadFrom(bytes.NewBuffer([]byte("hello world")))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, err = rw.(io.ReaderFrom).ReadFrom(struct{ io.Reader }{bytes.NewBuffer([]byte("hello world"))})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = responseProcessor(tx, req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if want, have := 201, res.Code; want != have {
		t.Errorf("unexpected status code, want %d, have %d", want, have)
	}
}

type testPusher struct{}

func (x *testPusher) Push(string, *http.PushOptions) error {
	return nil
}

type testHijacker struct{}

func (x *testHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, nil
}

func TestInterface(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	req, _ := http.NewRequest("GET", "", nil)
	res := httptest.NewRecorder()

	t.Run("default", func(t *testing.T) {
		rw, _ := wrap(struct {
			http.ResponseWriter
		}{
			res,
		}, req, tx)

		_, ok := rw.(http.Pusher)
		if ok {
			t.Errorf("expected the wrapped ResponseWriter to not implement http.Pusher")
		}

		_, ok = rw.(http.Hijacker)
		if ok {
			t.Errorf("expected the wrapped ResponseWriter to not implement http.Hijacker")
		}
	})

	t.Run("http.Pusher", func(t *testing.T) {
		rw, _ := wrap(struct {
			http.ResponseWriter
			http.Pusher
		}{
			res,
			&testPusher{},
		}, req, tx)

		_, ok := rw.(http.Pusher)
		if !ok {
			t.Errorf("expected the wrapped ResponseWriter to implement http.Pusher")
		}

		_, ok = rw.(http.Hijacker)
		if ok {
			t.Errorf("expected the wrapped ResponseWriter to not implement http.Hijacker")
		}
	})

	t.Run("http.Hijacker", func(t *testing.T) {
		rw, _ := wrap(struct {
			http.ResponseWriter
			http.Hijacker
		}{
			res,
			&testHijacker{},
		}, req, tx)

		_, ok := rw.(http.Hijacker)
		if !ok {
			t.Errorf("expected the wrapped ResponseWriter to implement http.Hijacker")
		}

		_, ok = rw.(http.Pusher)
		if ok {
			t.Errorf("expected the wrapped ResponseWriter to not implement http.Pusher")
		}
	})

	t.Run("http.Hijacker and http.Pusher", func(t *testing.T) {
		rw, _ := wrap(struct {
			http.ResponseWriter
			http.Hijacker
			http.Pusher
		}{
			res,
			&testHijacker{},
			&testPusher{},
		}, req, tx)

		_, ok := rw.(http.Hijacker)
		if !ok {
			t.Errorf("expected the wrapped ResponseWriter to implement http.Hijacker")
		}

		_, ok = rw.(http.Pusher)
		if !ok {
			t.Errorf("expected the wrapped ResponseWriter to implement http.Pusher")
		}
	})
}

// hijackableRecorder extends httptest.ResponseRecorder with http.Hijacker support
// to simulate what a real HTTP server connection provides.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	// Return a pipe-based connection to simulate a hijacked connection.
	server, client := net.Pipe()
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	// Close server side in the background as we don't need it in tests.
	go server.Close()
	return client, rw, nil
}

func newHijackableRecorder() *hijackableRecorder {
	return &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
}

func TestWebSocketUpgradeFlushesHeaders(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, _ := wrap(rec, r, tx)

	// Simulate a WebSocket upgrade response
	wrapped.Header().Set("Upgrade", "websocket")
	wrapped.Header().Set("Connection", "Upgrade")
	wrapped.WriteHeader(http.StatusSwitchingProtocols)

	// The 101 status should have been flushed to the underlying writer immediately
	if want, have := http.StatusSwitchingProtocols, rec.Code; want != have {
		t.Errorf("expected 101 to be flushed immediately for WebSocket upgrades, got %d", have)
	}
}

func TestHijackTrackerSetsIsHijacked(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On"))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, _ := wrap(rec, r, tx)

	hijacker, ok := wrapped.(http.Hijacker)
	if !ok {
		t.Fatal("expected wrapped writer to implement http.Hijacker")
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		t.Fatalf("unexpected error from Hijack: %v", err)
	}
	defer conn.Close()

	if !rec.hijacked {
		t.Error("expected underlying writer's Hijack to have been called")
	}
}

func TestResponseProcessorSkipsOnHijackedConnection(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecResponseBodyAccess On
		SecResponseBodyMimeType text/plain
	`))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, processResponse := wrap(rec, r, tx)

	// Simulate WebSocket upgrade
	wrapped.Header().Set("Upgrade", "websocket")
	wrapped.Header().Set("Connection", "Upgrade")
	wrapped.WriteHeader(http.StatusSwitchingProtocols)

	// Hijack the connection
	hijacker := wrapped.(http.Hijacker)
	conn, _, err := hijacker.Hijack()
	if err != nil {
		t.Fatalf("unexpected error from Hijack: %v", err)
	}
	defer conn.Close()

	// processResponse should return nil without attempting to write to the hijacked connection.
	if err := processResponse(tx, r); err != nil {
		t.Errorf("processResponse should not error on hijacked connection, got: %v", err)
	}
}

func TestWebSocketUpgradeDetectionOnly(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine DetectionOnly"))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := newHijackableRecorder()
	r, _ := http.NewRequest("GET", "/ws", nil)

	wrapped, processResponse := wrap(rec, r, tx)

	// Simulate WebSocket upgrade
	wrapped.Header().Set("Upgrade", "websocket")
	wrapped.Header().Set("Connection", "Upgrade")
	wrapped.WriteHeader(http.StatusSwitchingProtocols)

	if want, have := http.StatusSwitchingProtocols, rec.Code; want != have {
		t.Errorf("expected 101 to be flushed even in DetectionOnly mode, got %d", have)
	}

	// Hijack
	hijacker := wrapped.(http.Hijacker)
	conn, _, err := hijacker.Hijack()
	if err != nil {
		t.Fatalf("unexpected error from Hijack: %v", err)
	}
	defer conn.Close()

	if err := processResponse(tx, r); err != nil {
		t.Errorf("processResponse should succeed for WebSocket in DetectionOnly mode, got: %v", err)
	}
}

func TestRegularRequestStillProcessesResponseBody(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecResponseBodyAccess On
		SecResponseBodyMimeType text/plain
		SecRule RESPONSE_BODY "blocked-content" "id:100,phase:4,deny,status:403"
	`))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	defer tx.Close()

	rec := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"

	// Process request phases so the transaction is in the right state
	tx.ProcessConnection("127.0.0.1", 12345, "", 0)
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}

	wrapped, processResponse := wrap(rec, r, tx)

	wrapped.Header().Set("Content-Type", "text/plain")
	wrapped.WriteHeader(http.StatusOK)
	if _, err := wrapped.Write([]byte("blocked-content")); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	if err := processResponse(tx, r); err != nil {
		t.Fatalf("unexpected error from processResponse: %v", err)
	}

	// The phase 4 rule should have triggered an interruption, resulting in a 403
	if want, have := http.StatusForbidden, rec.Code; want != have {
		t.Errorf("expected status %d from response body rule, got %d", want, have)
	}
}

// TestWAFNotBypassedAfterWebSocketUpgrade verifies that a WebSocket upgrade
// on one connection does not cause the WAF to skip inspection of subsequent
// regular HTTP requests. Each request must get its own transaction.
func TestWAFNotBypassedAfterWebSocketUpgrade(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(`
		SecRuleEngine On
		SecRule ARGS:attack "evil" "id:1,phase:1,deny,status:403"
	`))
	if err != nil {
		t.Fatal(err)
	}

	handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))

	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	// Step 1: Perform a WebSocket upgrade request
	reqWS, err := http.NewRequest("GET", ts.URL+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqWS.Header.Set("Upgrade", "websocket")
	reqWS.Header.Set("Connection", "Upgrade")

	resWS, err := http.DefaultClient.Do(reqWS)
	if err != nil {
		t.Fatalf("WebSocket upgrade request failed: %v", err)
	}
	resWS.Body.Close()

	// Step 2: Send a regular request with a malicious payload — must be blocked
	resBlocked, err := http.Get(ts.URL + "/?attack=evil")
	if err != nil {
		t.Fatalf("regular request failed: %v", err)
	}
	resBlocked.Body.Close()

	if want, have := http.StatusForbidden, resBlocked.StatusCode; want != have {
		t.Errorf("WAF bypass: malicious request after WebSocket upgrade was not blocked, got status %d, want %d", have, want)
	}

	// Step 3: Verify a benign request still passes
	resOK, err := http.Get(ts.URL + "/?attack=benign")
	if err != nil {
		t.Fatalf("benign request failed: %v", err)
	}
	resOK.Body.Close()

	if want, have := http.StatusOK, resOK.StatusCode; want != have {
		t.Errorf("benign request after WebSocket upgrade was unexpectedly blocked, got status %d, want %d", have, want)
	}
}

func TestResponseBody(t *testing.T) {
	const (
		contentWithoutDataLeak    = "No data leak"
		contentWithDataLeak       = "data leak: SQL Error!!"
		limitActionReject         = "Reject"
		limitActionProcessPartial = "ProcessPartial"
	)
	testCases := []struct {
		name                      string
		content                   string
		responseBodyRelativeLimit int
		responseBodyLimitAction   string
		expectedStatusCode        int
	}{
		{
			name:                      "OneByteLongerThanLimitAndRejects",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: -1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusInternalServerError, // used to be StatusRequestEntityTooLarge, see https://github.com/corazawaf/coraza/pull/1379
		},
		{
			name:                      "JustEqualToLimitAndAccepts",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: 0,
			responseBodyLimitAction:   limitActionReject,
			// NOTE: According to https://coraza.io/docs/seclang/directives/#secresponsebodylimit
			// expectedStatusCode should be http.StatusOK, but actually it is http.StatusInternalServerError.
			// Coraza should be fixed.
			expectedStatusCode: http.StatusInternalServerError,
		},
		{
			name:                      "OneByteShorterThanLimitAndAccepts",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: 1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusOK,
		},
		{
			name:                      "DataLeakAndRejects",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: 1,
			responseBodyLimitAction:   limitActionReject,
			expectedStatusCode:        http.StatusForbidden,
		},
		{
			name:                      "LimitReachedNoDataLeakPartialProcessing",
			content:                   contentWithoutDataLeak,
			responseBodyRelativeLimit: -3,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusOK,
		},
		{
			name:                      "DataLeakFoundInPartialProcessing",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: -2,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusForbidden,
		},
		{
			name:                      "DataLeakAroundLimitPartialProcessing",
			content:                   contentWithDataLeak,
			responseBodyRelativeLimit: -3,
			responseBodyLimitAction:   limitActionProcessPartial,
			expectedStatusCode:        http.StatusOK,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			bodyLenThird := len(testCase.content) / 3
			bodyChunks := map[string][]string{
				"BodyInOneShot":     {testCase.content},
				"BodyInThreeChunks": {testCase.content[0:bodyLenThird], testCase.content[bodyLenThird : 2*bodyLenThird], testCase.content[2*bodyLenThird:]},
			}

			for name, chunks := range bodyChunks {
				t.Run(name, func(t *testing.T) {
					directives := fmt.Sprintf(`
						SecRuleEngine On
						SecResponseBodyAccess On
						SecResponseBodyMimeType text/plain
						SecResponseBodyLimit %d
						SecResponseBodyLimitAction %s
						SecRule RESPONSE_BODY "SQL Error" "id:100,phase:4,deny"
					`, len(testCase.content)+testCase.responseBodyRelativeLimit, testCase.responseBodyLimitAction)

					waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
					if err != nil {
						t.Fatal(err)
					}

					handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if len(chunks) == 1 {
							w.Header().Set("Content-Length", strconv.Itoa(len(testCase.content)))
						}
						w.Header().Set("Content-Type", "text/plain")
						for _, chunk := range chunks {
							if n, err := fmt.Fprint(w, chunk); err != nil {
								t.Logf("failed to write response: %s", err)
							} else if got, want := n, len(chunk); got != want {
								t.Errorf("written response byte count mismatch, got=%d, want=%d", got, want)
							}
							if f, ok := w.(http.Flusher); ok && len(chunks) > 1 {
								f.Flush()
							}
						}
					}))

					ts := httptest.NewServer(handler)
					t.Cleanup(ts.Close)

					res, err := http.Get(ts.URL)
					if err != nil {
						t.Fatalf("unexpected error performing request: %v", err)
					}
					defer res.Body.Close()

					if got, want := res.StatusCode, testCase.expectedStatusCode; got != want {
						t.Errorf("unexpected status code, got=%d, want=%d", got, want)
					}

					if testCase.expectedStatusCode == http.StatusOK {
						body, err := io.ReadAll(res.Body)
						if err != nil {
							t.Fatalf("failed to read response body: %v", err)
						}
						if got, want := string(body), testCase.content; got != want {
							t.Errorf("unexpected response body, got=%q, want=%q", got, want)
						}
					}
				})
			}
		})
	}
}

// TestOutboundDataErrorVariable verifies the documented behavior of OUTBOUND_DATA_ERROR:
//   - ProcessPartial: the variable is set to 1 and Phase 4 rules CAN inspect it.
//   - Reject: the variable is set internally but Phase 4 rules never run because the
//     transaction is interrupted immediately; error propagation goes via the connector.
func TestOutboundDataErrorVariable(t *testing.T) {
	const body = "response body that is intentionally long"

	t.Run("ProcessPartial_phase4RuleCanMatchOutboundDataError", func(t *testing.T) {
		// SecResponseBodyLimit is set smaller than the body so OUTBOUND_DATA_ERROR is
		// set to 1. With ProcessPartial, Phase 4 rules run on the partial body, so the
		// OUTBOUND_DATA_ERROR rule can fire and deny the response.
		directives := fmt.Sprintf(`
			SecRuleEngine On
			SecResponseBodyAccess On
			SecResponseBodyMimeType text/plain
			SecResponseBodyLimit %d
			SecResponseBodyLimitAction ProcessPartial
			SecRule OUTBOUND_DATA_ERROR "@eq 1" "phase:4,id:200,t:none,deny,status:413,msg:'Response body exceeded limit'"
		`, len(body)-5)

		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
		if err != nil {
			t.Fatal(err)
		}

		handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, body)
		}))

		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)

		res, err := http.Get(ts.URL)
		if err != nil {
			t.Fatalf("unexpected error performing request: %v", err)
		}
		res.Body.Close()

		// The phase:4 rule matched OUTBOUND_DATA_ERROR==1 and denied with 413.
		if got, want := res.StatusCode, http.StatusRequestEntityTooLarge; got != want {
			t.Errorf("expected status %d (phase:4 rule fired on OUTBOUND_DATA_ERROR), got %d", want, got)
		}
	})

	t.Run("Reject_interruptsBeforePhase4RulesRun", func(t *testing.T) {
		// With Reject mode, when the body exceeds the limit the transaction is interrupted
		// immediately. Phase 4 rules never execute, so the OUTBOUND_DATA_ERROR rule below
		// cannot fire. The connector enforces a 500 (internal server error) instead.
		directives := fmt.Sprintf(`
			SecRuleEngine On
			SecResponseBodyAccess On
			SecResponseBodyMimeType text/plain
			SecResponseBodyLimit %d
			SecResponseBodyLimitAction Reject
			SecRule OUTBOUND_DATA_ERROR "@eq 1" "phase:4,id:201,t:none,deny,status:413,msg:'Response body exceeded limit'"
		`, len(body)-5)

		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
		if err != nil {
			t.Fatal(err)
		}

		handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, body)
		}))

		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)

		res, err := http.Get(ts.URL)
		if err != nil {
			t.Fatalf("unexpected error performing request: %v", err)
		}
		res.Body.Close()

		// 500 from the immediate interruption — not 413 from the phase:4 rule (which
		// never ran) — confirms OUTBOUND_DATA_ERROR is inaccessible to rules in Reject mode.
		if got, want := res.StatusCode, http.StatusInternalServerError; got != want {
			t.Errorf("expected status %d (Reject interruption, phase:4 rule did not run), got %d", want, got)
		}
	})
}

// TestInboundDataErrorVariable verifies the documented behavior of INBOUND_DATA_ERROR:
//   - ProcessPartial: the variable is set to 1 and Phase 2 rules CAN inspect it.
//   - Reject: the variable is set internally but Phase 2 rules never run because the
//     transaction is interrupted immediately; error propagation goes via the connector.
func TestInboundDataErrorVariable(t *testing.T) {
	const body = "request body that is intentionally long enough to exceed a small limit"

	t.Run("ProcessPartial_phase2RuleCanMatchInboundDataError", func(t *testing.T) {
		// SecRequestBodyLimit is set smaller than the body so INBOUND_DATA_ERROR is
		// set to 1. With ProcessPartial, Phase 2 rules run on the partial body, so the
		// INBOUND_DATA_ERROR rule can fire and deny the request.
		directives := fmt.Sprintf(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRequestBodyLimit %d
			SecRequestBodyLimitAction ProcessPartial
			SecRule INBOUND_DATA_ERROR "@eq 1" "phase:2,id:202,t:none,deny,status:400,msg:'Request body exceeded limit'"
		`, len(body)-5)

		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
		if err != nil {
			t.Fatal(err)
		}

		handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)

		res, err := http.Post(ts.URL, "application/x-www-form-urlencoded", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("unexpected error performing request: %v", err)
		}
		res.Body.Close()

		// The phase:2 rule matched INBOUND_DATA_ERROR==1 and denied with 400.
		if got, want := res.StatusCode, http.StatusBadRequest; got != want {
			t.Errorf("expected status %d (phase:2 rule fired on INBOUND_DATA_ERROR), got %d", want, got)
		}
	})

	t.Run("Reject_interruptsBeforePhase2RulesRun", func(t *testing.T) {
		// With Reject mode, when the body exceeds the limit the transaction is interrupted
		// immediately. Phase 2 rules never execute, so the INBOUND_DATA_ERROR rule below
		// cannot fire. The connector enforces a 413 from the body-limit interruption instead.
		directives := fmt.Sprintf(`
			SecRuleEngine On
			SecRequestBodyAccess On
			SecRequestBodyLimit %d
			SecRequestBodyLimitAction Reject
			SecRule INBOUND_DATA_ERROR "@eq 1" "phase:2,id:203,t:none,deny,status:400,msg:'Request body exceeded limit'"
		`, len(body)-5)

		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
		if err != nil {
			t.Fatal(err)
		}

		handler := WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)

		res, err := http.Post(ts.URL, "application/x-www-form-urlencoded", bytes.NewBufferString(body))
		if err != nil {
			t.Fatalf("unexpected error performing request: %v", err)
		}
		res.Body.Close()

		// 413 from the immediate body-limit interruption — not 400 from the phase:2 rule
		// (which never ran) — confirms INBOUND_DATA_ERROR is inaccessible to rules in Reject mode.
		if got, want := res.StatusCode, http.StatusRequestEntityTooLarge; got != want {
			t.Errorf("expected status %d (Reject interruption, phase:2 rule did not run), got %d", want, got)
		}
	})
}
