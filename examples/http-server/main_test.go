package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestHttpServerTrueNegative(t *testing.T) {
	expectedStatusCode := 200
	if err := setupCoraza(); err != nil {
		panic(err)
	}
	testServer := httptest.NewServer(corazaRequestHandler(http.HandlerFunc(hello)))
	defer testServer.Close()

	// Performs an http request not matching any rule.
	resp, err := http.Get(testServer.URL + "/hello")
	if err != nil {
		log.Fatalln(err)
	}
	if resp.StatusCode != expectedStatusCode {
		log.Fatalln(errors.New("Returned status code:" + fmt.Sprint(resp.StatusCode) + ". Expected: " + strconv.Itoa(expectedStatusCode)))
	}
}

func TestHttpServerTruePositive(t *testing.T) {
	expectedStatusCode := 403
	if err := setupCoraza(); err != nil {
		panic(err)
	}
	testServer := httptest.NewServer(corazaRequestHandler(http.HandlerFunc(hello)))
	defer testServer.Close()

	// Performs an http request matching a rule.
	resp, err := http.Get(testServer.URL + "/hello?id=0")
	if err != nil {
		log.Fatalln(err)
	}
	if resp.StatusCode != expectedStatusCode {
		log.Fatalln(errors.New("Returned status code:" + fmt.Sprint(resp.StatusCode) + ". Expected: " + strconv.Itoa(expectedStatusCode)))
	}
}
