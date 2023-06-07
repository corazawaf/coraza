// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const configCheckStatusCode = 424
const healthCheckTimeout = 15 // Seconds

func RunTests(nulledBody bool, corazaHost string, httpbinHost string) error {
	healthEndPointUrl := "http://" + httpbinHost + "/status/200"
	urlUnfiltered := "http://" + corazaHost
	urlFiltered := urlUnfiltered + "/admin"
	urlEcho := urlUnfiltered + "/anything"
	urlFilteredRespHeader := urlUnfiltered + "/response-headers?pass=leak"

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
		{
			name:         "Coraza config check",
			url:          urlUnfiltered,
			expectedCode: configCheckStatusCode,
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
	client := http.Client{}
	for currentCheckIndex, healthCheck := range healthChecks {
		fmt.Printf("[%d/%d]Running health check: %s\n", currentCheckIndex+1, totalChecks, healthCheck.name)
		timeout := healthCheckTimeout
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		req, _ := http.NewRequest(http.MethodGet, healthCheck.url, nil)
		for range ticker.C {
			if healthCheck.expectedCode != configCheckStatusCode {
				//  The default e2e header is not added if we are checking that the expected config is loaded
				req.Header.Add("coraza-e2e", "ok")
			}
			resp, err := client.Do(req)
			fmt.Printf("[Wait] Waiting for %s. Timeout: %ds\n", healthCheck.url, timeout)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == healthCheck.expectedCode {
					fmt.Printf("[Ok] Check successful, got status code %d\n", resp.StatusCode)
					break
				}
				if healthCheck.expectedCode == configCheckStatusCode {
					return fmt.Errorf("configs check failed, got status code %d, expected %d. Please check configs used", resp.StatusCode, healthCheck.expectedCode)
				}
			}
			timeout--
			if timeout == 0 {
				return fmt.Errorf("timeout waiting for response from %s, make sure the server is running", healthCheck.url)
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
			return fmt.Errorf("could not make http request: %s", err)
		}
		for k, v := range test.headers {
			req.Header.Add(k, v)
		}
		req.Header.Add("coraza-e2e", "ok")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("could not do http request: %s", err)
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("could not read response body: %s", err)
		}

		if resp.StatusCode != test.expectedCode {
			// Some connectors (such as coraza-proxy-wasm) might not be able to change anymore the status code at phase:4,
			// therefore, if nulledBody parameter is true, we expect a 200, but with a nulled body
			if !(nulledBody && test.expectedEmptyBody && resp.StatusCode == 200 && test.expectedCode == 403) {
				return fmt.Errorf("unexpected status code, got %d, expected %d", resp.StatusCode, test.expectedCode)
			}
		}

		if test.expectedEmptyBody && string(respBody) != "" {
			// If an interruption happend at phase:4, some connectors (such as coraza-proxy-wasm) will override the response body with empty bytes
			for _, byte := range respBody {
				if byte != 0 {
					return fmt.Errorf("unexpected response body with body, got %s", string(respBody))
				}
			}
			fmt.Printf("[Ok] Response body filled of null bytes\n")
		}
		fmt.Printf("[Ok] Got status code %d, expected %d\n", resp.StatusCode, test.expectedCode)
	}
	return nil
}
