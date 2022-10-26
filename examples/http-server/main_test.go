package main

import (
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
	return httptest.NewServer(txhttp.WrapHandler(waf, t.Logf, http.HandlerFunc(exampleHandler)))
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

func TestHttpServer(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		expStatus int
		envVars   map[string]string
	}{
		{"negative", "/", 200, nil},
		{"positive for query parameter", "/?id=0", 403, nil},
		{
			"positive for response body",
			"/",
			403,
			map[string]string{
				"DIRECTIVES_FILE": "./testdata/response-body.conf",
				"RESPONSE_BODY":   "creditcard",
			},
		},
		{
			"positive for response header",
			"/",
			403,
			map[string]string{
				"DIRECTIVES_FILE":  "./testdata/response-headers.conf",
				"RESPONSE_HEADERS": "foo:bar",
			},
		},
	}
	// Perform tests
	for _, tc := range tests {
		tt := tc
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

			statusCode := doGetRequest(t, testServer.URL+tt.path)
			if want, have := tt.expStatus, statusCode; want != have {
				t.Errorf("Unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}
