package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	txhttp "github.com/redwanghb/coraza/v3/http"
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

// TestHttpServerConcurrent is meant to be run with the "-race" flag.
// Multiple requests are sent concurrently to the server and race conditions are checked.
// It is especially useful to ensure that rules and their metadata are not edited in an unsafe way
// after parsing time.
func TestHttpServerConcurrent(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		expStatus int
		body      []byte // if body is populated, POST request is sent
	}{
		{"negative", "/", 200, nil},
		{"positive for query parameter 1", "/?id=0", 403, nil},
		{"positive for request body", "/", 403, []byte("password")},
	}
	// Spin up the test server with default.conf configuration
	testServer := setupTestServer(t)
	defer testServer.Close()
	// a t.Run wraps all the concurrent tests and permits to close the server only once test is done
	// See https://github.com/golang/go/issues/17791
	t.Run("concurrent test", func(t *testing.T) {
		for _, tc := range tests {
			tt := tc
			for i := 0; i < 10; i++ {
				// Each test case is added 10 times and then run concurrently
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()
					var statusCode int
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
	})
}
