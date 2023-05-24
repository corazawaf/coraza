// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// TODO Expected Coraza configs
// ...
// ...
// CORAZA_HOST
// HTTPBIN_HOST
// CORAZA_ENVOY

// CORAZA_ENVOY=true go run .

const healthCheckTimeout = 15 // Seconds

func main() {
	// Initialize variables
	corazaEnvoy := false
	corazaEnvoyString := os.Getenv("CORAZA_ENVOY")
	if corazaEnvoyString == "true" {
		corazaEnvoy = true
	}
	corazaHost := os.Getenv("CORAZA_HOST")
	if corazaHost == "" {
		corazaHost = "localhost:8080"
	}
	httpbinHost := os.Getenv("HTTPBIN_HOST")
	if httpbinHost == "" {
		httpbinHost = "localhost:8081"
	}

	healthEndPointUrl := "http://" + httpbinHost + "/status/200"
	urlUnfiltered := "http://" + corazaHost
	urlFiltered := urlUnfiltered + "/admin"
	urlEcho := urlUnfiltered + "/anything"
	urlFilteredRespHeader := urlUnfiltered + "/status/406"

	healthChecks := []struct {
		name         string
		url          string
		expectedCode int
	}{
		{
			name:         "Backend health check",
			url:          healthEndPointUrl,
			expectedCode: 200,
		},
		{
			name:         "Coraza health check",
			url:          urlUnfiltered,
			expectedCode: 200,
		},
	}

	tests := []struct {
		name               string
		url                string
		headers            map[string]string
		payload            string
		httpMethod         string
		expectedCode       int
		expectedEmptyBody  bool
		expectedBodyString string
	}{
		{
			name:         "(onRequestheaders) Testing true negative request",
			url:          urlUnfiltered + "?arg=arg_1",
			httpMethod:   "GET",
			expectedCode: 200,
		},
		{
			name:              "(onRequestheaders) Testing true positive custom rule",
			url:               urlFiltered,
			httpMethod:        "GET",
			expectedCode:      403,
			expectedEmptyBody: true,
		},
		{
			name:         "(onRequestBody) Testing true negative request (body)",
			url:          urlEcho,
			httpMethod:   "POST",
			headers:      map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			payload:      "This is a payload",
			expectedCode: 200,
		},
		{
			name:         "(onRequestBody) Testing true positive request (body)",
			url:          urlUnfiltered,
			httpMethod:   "POST",
			headers:      map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			payload:      "maliciouspayload",
			expectedCode: 403,
		},
		{
			name:         "(onResponseHeaders) Testing true positive",
			url:          urlFilteredRespHeader,
			httpMethod:   "GET",
			expectedCode: 403,
		},
		{
			name:         "(onResponseBody) Testing true negative",
			url:          urlEcho,
			httpMethod:   "POST",
			headers:      map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			payload:      "Hello world",
			expectedCode: 200,
		},
		{
			name:              "(onResponseBody) Testing true positive",
			url:               urlEcho,
			httpMethod:        "POST",
			headers:           map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			payload:           "responsebodycode",
			expectedEmptyBody: true,
			expectedCode:      403,
		},
		{
			name:         "Testing XSS detection at request headers",
			url:          urlEcho + "?arg=<script>alert(0)</script>",
			httpMethod:   "GET",
			expectedCode: 403,
		},
		{
			name:         "Testing SQLi detection at request body",
			url:          urlEcho + "?arg=<script>alert(0)</script>",
			httpMethod:   "POST",
			headers:      map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			payload:      "1%27%20ORDER%20BY%203--%2B",
			expectedCode: 403,
		},
		{
			name: "Testing CRS rule 913100 sending malicious UA",
			url:  urlEcho,
			headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"User-Agent":   "Grabber/0.1 (X11; U; Linux i686; en-US; rv:1.7)",
			},
			httpMethod:   "GET",
			expectedCode: 403,
		},
	}

	// Check health endpoint
	totalChecks := len(healthChecks)
	for currentCheckIndex, healthCheck := range healthChecks {
		fmt.Printf("[%d/%d]Running health check: %s\n", currentCheckIndex+1, totalChecks, healthCheck.name)
		client := http.Client{}
		timeout := healthCheckTimeout
		tick := time.Tick(time.Second)
		for range tick {
			resp, err := client.Get(healthCheck.url)
			fmt.Printf("[Wait] Waiting for %s. Timeout: %ds\n", healthCheck.url, timeout)
			if err == nil && resp.StatusCode == http.StatusOK {
				fmt.Printf("[Ok] Health check successful, got status code %d\n", resp.StatusCode)
				break
			}
			timeout--
			if timeout == 0 {
				fmt.Printf("[Fail] Timeout waiting for response from %s, make sure the server is running.\n", healthCheck.url)
				os.Exit(1)
			}
		}
	}

	totalTests := len(tests)

	// Iterate over tests
	for currentTestIndex, test := range tests {
		fmt.Printf("[%d/%d] Running test: %s\n", currentTestIndex+1, totalTests, test.name)
		client := &http.Client{}
		payloadReader := io.Reader(nil)
		if test.payload != "" {
			payloadReader = strings.NewReader(test.payload)
		}
		req, err := http.NewRequest(test.httpMethod, test.url, payloadReader)
		if err != nil {
			fmt.Printf("Error: could not make http request: %s\n", err)
			os.Exit(1)
		}
		for k, v := range test.headers {
			req.Header.Add(k, v)
		}
		res, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error: could not do http request: %s\n", err)
			os.Exit(1)
		}
		if res.StatusCode != test.expectedCode {
			// Envoy can not return anymore a 403 at phase:4 therefore we expect a 200, but with an empty body
			if !(corazaEnvoy && test.expectedEmptyBody && res.StatusCode == 200 && test.expectedCode == 403) {
				fmt.Printf("[Fail] Expected status code %d, got %d from %s\n", test.expectedCode, res.StatusCode, test.url)
				os.Exit(1)
			}
		}
		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			fmt.Printf("Error: could not read response body: %s\n", err)
			os.Exit(1)
		}
		if test.expectedEmptyBody && string(resBody) != "" {
			// If an interruption happend at phase:4, Envoy will override the response body with empty bytes
			for _, byte := range resBody {
				if byte != 0 {
					fmt.Printf("[Fail] Unexpected response with body, got %s\n", string(resBody))
					os.Exit(1)

				}
			}
			fmt.Printf("[Ok] Response body filled of null bytes\n")
		}
		// if string(resBody) != test.expectedBody {
		// 	fmt.Printf("[Fail] Expected body %s, got %s\n", test.expectedBody, string(resBody))
		// 	os.Exit(1)
		// }
		fmt.Printf("[Ok] Got status code %d, expected %d\n", res.StatusCode, test.expectedCode)
	}
}
