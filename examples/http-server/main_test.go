package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	waf, err := setupCoraza()
	if err != nil {
		panic(err)
	}
	return httptest.NewServer(corazaRequestHandler(waf, http.HandlerFunc(hello)))
}

func doGetRequest(t *testing.T, getPath string) int {
	t.Helper()
	resp, err := http.Get(getPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
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
			if statusCode != tt.expStatus {
				t.Errorf("Unexpected status code, want: %d, have: %d", tt.expStatus, statusCode)
			}
		})
	}
}
