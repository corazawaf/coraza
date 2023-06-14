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

const (
	configCheckStatusCode = 424
	healthCheckTimeout    = 15 // Seconds
)

type Config struct {
	NulledBody        bool
	ProxiedEntrypoint string
	HttpbinEntrypoint string
}

func Run(cfg Config) error {
	healthURL := cfg.HttpbinEntrypoint + "/status/200"
	baseProxyURL := cfg.ProxiedEntrypoint
	echoProxiedURL := baseProxyURL + "/anything"

	healthChecks := []struct {
		name         string
		url          string
		expectedCode int
	}{
		{
			name:         "Health check",
			url:          healthURL,
			expectedCode: 200,
		},
		{
			name:         "Proxy check",
			url:          baseProxyURL,
			expectedCode: 200,
		},
		{
			name:         "Header check",
			url:          baseProxyURL,
			expectedCode: configCheckStatusCode,
		},
	}

	tests := []struct {
		name               string
		requestURL         string
		requestHeaders     map[string]string
		requestBody        string
		requestMethod      string
		expectedStatusCode int
		expectedEmptyBody  bool
		expectedBody       string
	}{
		{
			name:               "Legit request",
			requestURL:         baseProxyURL + "?arg=arg_1",
			requestMethod:      "GET",
			expectedStatusCode: 200,
		},
		{
			name:               "Denied request by URL",
			requestURL:         baseProxyURL + "/admin",
			requestMethod:      "GET",
			expectedStatusCode: 403,
			expectedEmptyBody:  true,
		},
		{
			name:               "Legit request with legit body",
			requestURL:         echoProxiedURL,
			requestMethod:      "POST",
			requestHeaders:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestBody:        "This is a legit payload",
			expectedStatusCode: 200,
		},
		{
			name:               "Denied request with a malicious request body",
			requestURL:         echoProxiedURL,
			requestMethod:      "POST",
			requestBody:        "maliciouspayload",
			expectedStatusCode: 403,
		},
		{
			name:               "Denied request with a malicious response header",
			requestURL:         baseProxyURL + "/response-headers?pass=leak",
			requestMethod:      "GET",
			expectedStatusCode: 403,
		},
		{
			name:               "Denied request with a malicious response body",
			requestURL:         echoProxiedURL,
			requestMethod:      "POST",
			requestBody:        "responsebodycode",
			expectedEmptyBody:  true,
			expectedStatusCode: 403,
		},
		{
			name:               "Denied request with XSS query parameters",
			requestURL:         echoProxiedURL + "?arg=<script>alert(0)</script>",
			requestMethod:      "GET",
			expectedStatusCode: 403,
		},
		{
			name:               "Denied request with SQLi query parameters",
			requestURL:         echoProxiedURL,
			requestMethod:      "POST",
			requestHeaders:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestBody:        "1%27%20ORDER%20BY%203--%2B",
			expectedStatusCode: 403,
		},
		{
			name:       "CRS rule 913100 sending malicious UA",
			requestURL: echoProxiedURL,
			requestHeaders: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"User-Agent":   "Grabber/0.1 (X11; U; Linux i686; en-US; rv:1.7)",
			},
			requestMethod:      "GET",
			expectedStatusCode: 403,
		},
	}

	// Check health endpoint
	client := http.DefaultClient
	for currentCheckIndex, healthCheck := range healthChecks {
		fmt.Printf("[%d/%d] Running health check: %s\n", currentCheckIndex+1, len(healthChecks), healthCheck.name)
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

	// Iterate over tests
	for currentTestIndex, test := range tests {
		fmt.Printf("[%d/%d] Running test: %s\n", currentTestIndex+1, len(tests), test.name)
		var requestBody io.Reader
		if test.requestBody != "" {
			requestBody = strings.NewReader(test.requestBody)
		}

		req, err := http.NewRequest(test.requestMethod, test.requestURL, requestBody)
		if err != nil {
			return fmt.Errorf("could not make http request: %v", err)
		}

		if test.requestMethod == "POST" {
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		}
		for k, v := range test.requestHeaders {
			req.Header.Add(k, v)
		}
		req.Header.Add("coraza-e2e", "ok")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("could not do http request: %v", err)
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("could not read response body: %v", err)
		}

		if resp.StatusCode != test.expectedStatusCode {
			// Some connectors (such as coraza-proxy-wasm) might not be able to change anymore the status code at phase:4,
			// therefore, if nulledBody parameter is true, we expect a 200, but with a nulled body
			if !(cfg.NulledBody && test.expectedEmptyBody && resp.StatusCode == 200 && test.expectedStatusCode == 403) {
				return fmt.Errorf("unexpected status code, got %d, expected %d", resp.StatusCode, test.expectedStatusCode)
			}
		}

		if test.expectedEmptyBody && len(respBody) != 0 {
			// If an interruption happened at phase:4, some connectors (such as coraza-proxy-wasm) will override the response
			// body with empty bytes
			for _, b := range respBody {
				if b != 0 {
					return fmt.Errorf("unexpected response body with body, got %s", string(respBody))
				}
			}
			fmt.Printf("[Ok] Response body filled with null bytes\n")
		}

		fmt.Printf("[Ok] Got status code %d, expected %d\n", resp.StatusCode, test.expectedStatusCode)
	}
	return nil
}
