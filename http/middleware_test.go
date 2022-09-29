// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

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
)

func createWAF() coraza.WAF {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithDirectives(`
		# This is a comment
		SecDebugLogLevel 9
		SecRequestBodyAccess On
		SecRule ARGS:id "@eq 0" "id:1, phase:1,deny, status:403,msg:'Invalid id',log,auditlog"
		SecRule REQUEST_BODY "@contains eval" "id:100, phase:2,deny, status:403,msg:'Invalid request body',log,auditlog"
		SecRule RESPONSE_BODY "@contains dangerousstring" "id:200, phase:4,deny, status:403,msg:'Invalid response body',log,auditlog"
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
			expectedStatus: 200,
		},
		"args blocking": {
			reqURI:         "/hello?id=0",
			expectedStatus: 403,
		},
		"request body blocking": {
			reqURI:         "/hello",
			reqBody:        "Lorem ipsum denystring dolor sit",
			expectedStatus: 403,
		},
		"response body blocking": {
			reqURI:         "/hello",
			respBody:       "Lorem ipsum dangerousstring dolor sit",
			expectedStatus: 403,
		},
	}

	// Perform tests
	for name, tCase := range tests {
		t.Run(name, func(t *testing.T) {
			// Spin up the test server
			srv := httptest.NewServer(WrapHandler(createWAF(), t.Logf, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				fmt.Fprintf(w, tCase.respBody)
			})))
			defer srv.Close()

			var reqBody io.Reader
			if tCase.reqBody != "" {
				reqBody = strings.NewReader(tCase.reqBody)
			}
			req, _ := http.NewRequest("POST", srv.URL+tCase.reqURI, reqBody)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("unexpected error when performing the request: %v", err)
			}

			if want, have := tCase.expectedStatus, res.StatusCode; want != have {
				t.Errorf("unexpected status code, want: %d, have: %d", want, have)
			}

			err = res.Body.Close()
			if err != nil {
				t.Errorf("failed to close the body: %v", err)
			}

		})
	}
}
