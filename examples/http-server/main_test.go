package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func corazaGetRequest(getPath string) (int, string) {
	if err := setupCoraza(); err != nil {
		panic(err)
	}
	testServer := httptest.NewServer(corazaRequestHandler(http.HandlerFunc(hello)))
	defer testServer.Close()

	// Performs a get request
	resp, err := http.Get(testServer.URL + getPath)
	if err != nil {
		log.Fatalln(err)
	}
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		bodyString := string(bodyBytes)
		return resp.StatusCode, bodyString
	}
	return resp.StatusCode, ""
}

func TestHttpServerTrueNegative(t *testing.T) {
	expectedStatusCode := 200
	statusCode, _ := corazaGetRequest("/hello")
	if statusCode != expectedStatusCode {
		log.Fatalln(errors.New("Returned status code:" + fmt.Sprint(statusCode) + ". Expected: " + strconv.Itoa(expectedStatusCode)))
	}
}

func TestHttpServerTruePositive(t *testing.T) {
	expectedStatusCode := 403
	statusCode, _ := corazaGetRequest("/hello?id=0")
	if statusCode != expectedStatusCode {
		log.Fatalln(errors.New("Returned status code:" + fmt.Sprint(statusCode) + ". Expected: " + strconv.Itoa(expectedStatusCode)))
	}
}
