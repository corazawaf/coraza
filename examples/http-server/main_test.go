package main

import (
	"log"
	"net/http"
	"net/http/httptest"
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
	}{
		{"negative", "/hello", 200},
		{"positive", "/hello?id=0", 403},
	}
	// Spin up the test server
	testServer := setupTestServer(t)
	defer testServer.Close()

	// Perform tests
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			statusCode := doGetRequest(t, testServer.URL+tt.path)
			if want, have := tt.expStatus, statusCode; want != have {
				t.Errorf("Unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}
