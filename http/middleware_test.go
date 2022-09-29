// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Channels and goroutines are not going to work with tinygo
//go:build !tinygo
// +build !tinygo

package http

import (
	"fmt"
	"io"
	"log"
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
	t     *testing.T
	level loggers.LogLevel
}

func (l *debugLogger) Info(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelInfo {
		l.t.Logf(message, args...)
	}
}

func (l *debugLogger) Warn(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelWarn {
		l.t.Logf(message, args...)
	}
}

func (l *debugLogger) Error(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelError {
		l.t.Logf(message, args...)
	}
}

func (l *debugLogger) Debug(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelDebug {
		l.t.Logf(message, args...)
	}
}

func (l *debugLogger) Trace(message string, args ...interface{}) {
	if l.level >= loggers.LogLevelTrace {
		l.t.Logf(message, args...)
	}
}

func (l *debugLogger) SetLevel(level loggers.LogLevel) {
	l.level = level
}

func (l *debugLogger) SetOutput(w io.Writer) {
	fmt.Println("ignoring SecDebugLog directive, debug logs are always routed to proxy logs")
}

func createWAF(t *testing.T) coraza.WAF {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
		# This is a comment
		SecDebugLogLevel 5
		SecRequestBodyAccess On
		SecResponseBodyAccess On
		SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
		SecRule REQUEST_BODY "@contains eval" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
		SecRule RESPONSE_BODY "@contains password" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
	`).WithErrorLogger(errLogger(t)).WithDebugLogger(&debugLogger{t: t}))
	if err != nil {
		log.Fatal(err)
	}
	return waf
}

func TestHttpServer(t *testing.T) {
	tests := map[string]struct {
		reqURI         string
		reqBody        string
		respBody       string
		expectedStatus int
	}{
		"no blocking": {
			reqURI:         "/hello",
			expectedStatus: 201,
		},
		"args blocking": {
			reqURI:         "/hello?id=0",
			expectedStatus: 403,
		},
		"request body blocking": {
			reqURI:         "/hello",
			reqBody:        "eval('cat /etc/passwd')",
			expectedStatus: 403,
		},
		// TODO(jcchavezs): sort out why response body evaluation isn't happening despite "SecResponseBodyAccess On"
		// "response body blocking": {
		//	reqURI:         "/hello",
		//	respBody:       "passord=xxxx",
		//		expectedStatus: 403,
		// },
	}

	// Perform tests
	for name, tCase := range tests {
		t.Run(name, func(t *testing.T) {
			serverErrC := make(chan error, 1)
			defer close(serverErrC)

			// Spin up the test server
			srv := httptest.NewServer(WrapHandler(createWAF(t), t.Logf, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				_, err := w.Write([]byte(tCase.respBody))
				if err != nil {
					serverErrC <- err
				}
				w.Header().Add("coraza-middleware", "true")
				w.WriteHeader(201)
			})))
			defer srv.Close()

			var reqBody io.Reader
			if tCase.reqBody != "" {
				reqBody = strings.NewReader(tCase.reqBody)
			}
			req, _ := http.NewRequest("POST", srv.URL+tCase.reqURI, reqBody)
			// TODO(jcchavezs): Fix it once the discussion in https://github.com/corazawaf/coraza/issues/438 is settled
			req.Header.Add("content-type", "application/x-www-form-urlencoded")
			res, err := http.DefaultClient.Do(req)
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

			if want, have := tCase.respBody, string(resBody); want != have {
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
