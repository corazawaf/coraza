package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	txhttp "github.com/corazawaf/coraza/v3/http"
)

func setupTestServer(t *testing.T, directiveFile string) *httptest.Server {
	t.Helper()
	waf := createWAF(directiveFile)
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

func TestSetVarRequestCountForSession(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		header         map[string]string
		directivesFile string
		expStatuses    []int
	}{
		{
			"negative for the first 2 requests and positive for 3d",
			"/",
			map[string]string{
				"X-Session-ID": "unique-session-id",
			},
			"./testdata/setvar-request-count.conf",
			[]int{200, 200, 403},
		},
	}
	// Perform tests
	for _, tc := range tests {
		tt := tc
		var statusCode int
		t.Run(tt.name, func(t *testing.T) {
			// Spin up the test server
			testServer := setupTestServer(t, tt.directivesFile)
			defer testServer.Close()

			for _, expStatus := range tt.expStatuses {
				statusCode = doGetRequest(t, testServer.URL+tt.path)
				if expStatus != statusCode {
					t.Errorf("Unexpected status code, want: %d, have: %d", expStatus, statusCode)
				}
			}
		})
	}
}
