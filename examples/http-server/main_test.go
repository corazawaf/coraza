package main

import (
	"bytes"
	"io"
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

func doPostRequest(t *testing.T, postPath string, data []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(postPath, "application/x-www-form-urlencoded", bytes.NewBuffer(data))
	if err != nil {
		log.Fatalln(err)
	}
	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatalln(err)
	}
	return resp.StatusCode, respBody
}

func TestHttpServer(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		expStatus       int
		envVars         map[string]string
		body            []byte // if body is populated, POST request is sent
		expResponseBody []byte
	}{
		{"negative", "/", 200, nil, nil, nil},
		{"positive for query parameter", "/?id=0", 403, nil, nil, nil},
		{
			"positive for response body",
			"/",
			403,
			map[string]string{
				"DIRECTIVES_FILE": "./testdata/response-body.conf",
				"RESPONSE_BODY":   "creditcard",
			},
			nil,
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
			nil,
		},
		{
			"positive for request body limit reject",
			"/",
			403,
			map[string]string{
				"DIRECTIVES_FILE": "./testdata/request-body-limits-reject.conf",
			},
			[]byte("beyond the limit"),
			nil,
		},
		{
			"positive for request body process partial (payload inside processed body)",
			"/",
			403,
			map[string]string{
				"DIRECTIVES_FILE": "./testdata/request-body-limits-processpartial.conf",
			},
			[]byte("script not beyond the limit"),
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
			nil,
		},
		// TODO(M4tteoP) uncomment after merging WriteRsponseBody logic
		// {
		// 	"positive for response body limit reject",
		// 	"/",
		// 	403,
		// 	map[string]string{
		// 		"DIRECTIVES_FILE": "./testdata/response-body-limits-reject.conf",
		// 		"RESPONSE_BODY":   "response body beyond the limit",
		// 	},
		// 	nil,
		// 	nil,
		// },
		// {
		// 	"positive for response body process partial (payload inside processed body)",
		// 	"/",
		// 	403,
		// 	map[string]string{
		// 		"DIRECTIVES_FILE": "./testdata/response-body-limits-processpartial.conf",
		// 		"RESPONSE_BODY":   "leakedpassword response body beyond the limit",
		// 	},
		// 	nil,
		// 	nil,
		// },
		// {
		// 	"negative for response body process partial (payload beyond processed body)",
		// 	"/",
		// 	200,
		// 	map[string]string{
		// 		"DIRECTIVES_FILE": "./testdata/response-body-limits-processpartial.conf",
		// 		"RESPONSE_BODY":   "response body beyond the limit leakedpassword",
		// 	},
		// 	nil,
		// 	[]byte("response body beyond the limit leakedpassword"),
		// },
	}
	// Perform tests
	for _, tc := range tests {
		tt := tc
		var statusCode int
		var responseBody []byte
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
				statusCode, responseBody = doPostRequest(t, testServer.URL+tt.path, tt.body)
				if tt.expResponseBody != nil {
					if bytes.Compare(tt.expResponseBody, responseBody) != 0 {
						t.Errorf("Unexpected response body, want: %s, have: %s", string(tt.expResponseBody), string(responseBody))
					}
				}
			}
			if want, have := tt.expStatus, statusCode; want != have {
				t.Errorf("Unexpected status code, want: %d, have: %d", want, have)
			}
		})
	}
}
