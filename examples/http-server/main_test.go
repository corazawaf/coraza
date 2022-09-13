package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	if err := setupCoraza(); err != nil {
		panic(err)
	}
	return httptest.NewServer(corazaRequestHandler(http.HandlerFunc(hello)))
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

func TestHttpServerTrueNegative(t *testing.T) {
	testServer := setupTestServer(t)
	defer testServer.Close()
	expectedStatusCode := 200
	statusCode := doGetRequest(t, testServer.URL+"/hello")
	if statusCode != expectedStatusCode {
		t.Errorf("Unexpected status code, want: %d, have: %d", statusCode, expectedStatusCode)
	}
}

func TestHttpServerTruePositive(t *testing.T) {
	testServer := setupTestServer(t)
	defer testServer.Close()
	expectedStatusCode := 403
	statusCode := doGetRequest(t, testServer.URL+"/hello?id=0")
	if statusCode != expectedStatusCode {
		t.Errorf("Unexpected status code, want: %d, have: %d", statusCode, expectedStatusCode)
	}
}
