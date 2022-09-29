// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func createWAF() coraza.WAF {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
		# This is a comment
		SecDebugLogLevel 9
		SecRequestBodyAccess On
		SecResponseBodyAccess On
		SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
		SecRule REQUEST_BODY "@contains eval" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
		SecRule RESPONSE_BODY "@contains password" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
	`))
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
			srv := httptest.NewServer(WrapHandler(createWAF(), t.Logf, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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
