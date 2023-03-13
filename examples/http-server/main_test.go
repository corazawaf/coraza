package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	txhttp "github.com/corazawaf/coraza/v3/http"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	waf := createWAF()
	return httptest.NewServer(txhttp.WrapHandler(waf, http.HandlerFunc(exampleHandler)))
}

func doGetRequest(t *testing.T, getPath string) int {
	t.Helper()
	resp, err := http.Get(getPath)
	if err != nil {
		log.Fatalln(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func doPostRequest(t *testing.T, postPath string, data []byte) int {
	t.Helper()
	resp, err := http.Post(postPath, "application/x-www-form-urlencoded", bytes.NewBuffer(data))
	if err != nil {
		log.Fatalln(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestHttpServer(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		expStatus int
		envVars   map[string]string
		body      []byte // if body is populated, POST request is sent
	}{
		{"negative", "/", 200, nil, nil},
		{"positive for query parameter", "/?id=0", 403, nil, nil},
		{
			"positive for response body",
			"/",
			403,
			map[string]string{
				"DIRECTIVES_FILE": "./testdata/response-body.conf",
				"RESPONSE_BODY":   "creditcard",
			},
			nil,
		},
		{
			"positive for response header",
			"/",
			403,
			map[string]string{
				"DIRECTIVES_FILE":  "./testdata/response-headers.conf",
				"RESPONSE_HEADERS": "foo:bar",
			},
			nil,
		},
		{
			"negative for request body process partial (payload beyond processed body)",
			"/",
			200,
			map[string]string{
				"DIRECTIVES_FILE": "./testdata/request-body-limits-processpartial.conf",
			},
			[]byte("beyond the limit script"),
		},
		{
			"positive for response body limit reject",
			"/",
			413,
			map[string]string{
				"DIRECTIVES_FILE": "./testdata/response-body-limits-reject.conf",
				"RESPONSE_BODY":   "response body beyond the limit",
			},
			nil,
		},
	}
	// Perform tests
	for _, tc := range tests {
		tt := tc
		var statusCode int
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.envVars) > 0 {
				for k, v := range tt.envVars {
					os.Setenv(k, v)
					defer os.Unsetenv(k)
				}
			}

			// Spin up the test server
			testServer := setupTestServer(t)
			defer testServer.Close()
			if tt.body == nil {
				statusCode = doGetRequest(t, testServer.URL+tt.path)
			} else {
				statusCode = doPostRequest(t, testServer.URL+tt.path, tt.body)
			}
			if want, have := tt.expStatus, statusCode; want != have {
				t.Errorf("Unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}
