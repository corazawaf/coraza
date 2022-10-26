package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	txhttp "github.com/corazawaf/coraza/v3/http"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	waf := createWAF()
	return httptest.NewServer(txhttp.WrapHandler(waf, t.Logf, http.HandlerFunc(hello)))
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
		envVar    string
	}{
		{"negative", "/hello", 200, ""},
		{"positive", "/hello?id=0", 403, ""},
		{"positive", "/hello", 403, "RESPONSE_BODY=creditcard"},
		{"positive", "/hello", 403, "RESPONSE_HEADERS=foo:bar"},
	}
	// Spin up the test server
	testServer := setupTestServer(t)
	defer testServer.Close()

	// Perform tests
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			if tt.envVar != "" {
				kv := strings.Split(tt.envVar, "=")
				os.Setenv(kv[0], kv[1])
				defer os.Unsetenv(kv[0])
			}
			statusCode := doGetRequest(t, testServer.URL+tt.path)
			if want, have := tt.expStatus, statusCode; want != have {
				t.Errorf("Unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}
