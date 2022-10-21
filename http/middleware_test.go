// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// tinygo does not support net.http so this package is not needed for it
//go:build !tinygo
// +build !tinygo

package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/loggers"
	"github.com/corazawaf/coraza/v3/types"
)

func errLogger(t *testing.T) func(rule types.MatchedRule) {
	return func(rule types.MatchedRule) {
		t.Log(rule.ErrorLog(0))
	}
}

type debugLogger struct {
	t *testing.T
}

func (l *debugLogger) Info(message string, args ...interface{}) {
	l.t.Logf(message, args...)
}

func (l *debugLogger) Warn(message string, args ...interface{}) {
	l.t.Logf(message, args...)
}

func (l *debugLogger) Error(message string, args ...interface{}) {
	l.t.Logf(message, args...)
}

func (l *debugLogger) Debug(message string, args ...interface{}) {
	l.t.Logf(message, args...)
}

func (l *debugLogger) Trace(message string, args ...interface{}) {
	l.t.Logf(message, args...)
}

func (l *debugLogger) SetLevel(level loggers.LogLevel) {
	l.t.Logf("Setting level to %q", level.String())
}

func (l *debugLogger) SetOutput(w io.WriteCloser) {
	l.t.Log("ignoring SecDebugLog directive, debug logs are always routed to proxy logs")
}

func createWAF(t *testing.T) coraza.WAF {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
		# This is a comment
		SecDebugLogLevel 5
		SecRequestBodyAccess On
		SecResponseBodyAccess On
		SecResponseBodyMimeType text/plain
		SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
		SecRule REQUEST_BODY "@contains eval" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
		SecRule RESPONSE_BODY "@contains password" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
	`).WithErrorLogger(errLogger(t)).WithDebugLogger(&debugLogger{t: t}))
	if err != nil {
		t.Fatal(err)
	}
	return waf
}

func TestHttpServer(t *testing.T) {
	tests := map[string]struct {
		http2            bool
		reqURI           string
		reqBody          string
		respBody         string
		expectedProto    string
		expectedStatus   int
		expectedRespBody string
	}{
		"no blocking": {
			reqURI:         "/hello",
			expectedProto:  "HTTP/1.1",
			expectedStatus: 201,
		},
		"no blocking HTTP/2": {
			http2:          true,
			reqURI:         "/hello",
			expectedProto:  "HTTP/2.0",
			expectedStatus: 201,
		},
		"args blocking": {
			reqURI:         "/hello?id=0",
			expectedProto:  "HTTP/1.1",
			expectedStatus: 403,
		},
		"request body blocking": {
			reqURI:         "/hello",
			reqBody:        "eval('cat /etc/passwd')",
			expectedProto:  "HTTP/1.1",
			expectedStatus: 403,
		},
		"response body not blocking": {
			reqURI:           "/hello",
			respBody:         "true negative response body",
			expectedProto:    "HTTP/1.1",
			expectedStatus:   201,
			expectedRespBody: "true negative response body",
		},
		"response body blocking": {
			reqURI:           "/hello",
			respBody:         "password=xxxx",
			expectedProto:    "HTTP/1.1",
			expectedStatus:   201,
			expectedRespBody: "", // blocking at response body phase means returning it empty
		},
	}

	// Perform tests
	for name, tCase := range tests {
		t.Run(name, func(t *testing.T) {
			serverErrC := make(chan error, 1)
			defer close(serverErrC)

			// Spin up the test server
			ts := httptest.NewUnstartedServer(WrapHandler(createWAF(t), t.Logf, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if want, have := tCase.expectedProto, req.Proto; want != have {
					t.Errorf("unexpected proto, want: %s, have: %s", want, have)
				}

				w.Header().Set("Content-Type", "text/plain")
				_, err := w.Write([]byte(tCase.respBody))
				if err != nil {
					serverErrC <- err
				}
				w.Header().Add("coraza-middleware", "true")
				w.WriteHeader(201)
			})))
			if tCase.http2 {
				ts.EnableHTTP2 = true
				ts.StartTLS()
			} else {
				ts.Start()
			}
			defer ts.Close()

			var reqBody io.Reader
			if tCase.reqBody != "" {
				reqBody = strings.NewReader(tCase.reqBody)
			}
			req, _ := http.NewRequest("POST", ts.URL+tCase.reqURI, reqBody)
			// TODO(jcchavezs): Fix it once the discussion in https://github.com/corazawaf/coraza/issues/438 is settled
			req.Header.Add("content-type", "application/x-www-form-urlencoded")
			res, err := ts.Client().Do(req)
			if err != nil {
				t.Fatalf("unexpected error when performing the request: %v", err)
			}

			if want, have := tCase.expectedStatus, res.StatusCode; want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", want, have)
			}

			resBody, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("unexpected error when reading the response body: %v", err)
			}

			if want, have := tCase.expectedRespBody, string(resBody); want != have {
				t.Errorf("unexpected response body, want: %q, have %q", want, have)
			}

			err = res.Body.Close()
			if err != nil {
				t.Errorf("failed to close the body: %v", err)
			}

			select {
			case err = <-serverErrC:
				t.Errorf("unexpected error from server when writing response body: %v", err)
			default:
				return
			}
		})
	}
}
