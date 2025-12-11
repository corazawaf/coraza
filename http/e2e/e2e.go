// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

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

	Directives = `
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType application/json
# Custom rule for Coraza config check (ensuring that these configs are used)
SecRule &REQUEST_HEADERS:coraza-e2e "@eq 0" "id:100,phase:1,deny,status:424,log,msg:'Coraza E2E - Missing header'"
# Custom rules for e2e testing
SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,log,deny"
SecRule REQUEST_BODY "@rx maliciouspayload" "id:102,phase:2,t:lowercase,log,deny"
SecRule RESPONSE_HEADERS:pass "@rx leak" "id:103,phase:3,t:lowercase,log,deny"
SecRule RESPONSE_BODY "@contains responsebodycode" "id:104,phase:4,t:lowercase,log,deny"
# Custom rules mimicking the following CRS rules: 941100, 942100, 913100
SecRule ARGS_NAMES|ARGS "@detectXSS" "id:9411,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,log,deny"
SecRule ARGS_NAMES|ARGS "@detectSQLi" "id:9421,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,multiMatch,log,deny"
SecRule REQUEST_HEADERS:User-Agent "@pm grabber masscan" "id:9131,phase:1,t:none,log,deny"
`
	DirectivesStreamedResponse = `
SecRuleEngine On
SecRequestBodyAccess Off
# Custom rule for Coraza config check (ensuring that these configs are used)
SecRule &REQUEST_HEADERS:coraza-e2e "@eq 0" "id:100,phase:1,deny,status:424,log,msg:'Coraza E2E - Missing header'"
`
)

type Config struct {
	NulledBody        bool
	ProxiedEntrypoint string
	HttpbinEntrypoint string
}

// statusCodeExpectation is a function that checks the status code of a response
// Some connectors (such as coraza-proxy-wasm) might not be able to change anymore the status code at phase:4,
// therefore, if nulledBody parameter is true, we expect a 200, but with a nulled body
type statusCodeExpectation func(int) error

func expectStatusCode(expectedCode int) statusCodeExpectation {
	return func(code int) error {
		if code != expectedCode {
			return fmt.Errorf("expected status code %d, got %d", expectedCode, code)
		}

		return nil
	}
}

func expectNulledBodyStatusCode(nulledBody bool, expectedEmptyBodyCode, expectedNulledBodyCode int) statusCodeExpectation {
	return func(code int) error {
		if nulledBody {
			if code != expectedNulledBodyCode {
				return fmt.Errorf("expected status code %d, got %d", expectedNulledBodyCode, code)
			}

			return nil
		}

		if code != expectedEmptyBodyCode {
			return fmt.Errorf("expected status code %d, got %d", expectedEmptyBodyCode, code)
		}

		return nil
	}
}

// bodyExpectation sets a function to check the body expectations.
// Some connectors (such as coraza-proxy-wasm) might not be able to change anymore the status code at phase:4,
// therefore, if nulledBody parameter is true, we expect a 200, but with a nulled body
type bodyExpectation func(int, []byte) error

func expectEmptyOrNulledBody(nulledBody bool) bodyExpectation {
	return func(contentLength int, body []byte) error {
		if nulledBody {
			if contentLength == 0 {
				return fmt.Errorf("expected nulled body, got content-length 0")
			}

			if len(body) == 0 {
				return fmt.Errorf("expected nulled body, got empty body")
			}

			for _, b := range body {
				if b != 0 {
					return fmt.Errorf("expected nulled body, got %q", string(body))
				}
			}

			return nil
		}

		if contentLength != 0 {
			return fmt.Errorf("expected empty body, got content-length %d", contentLength)
		}

		if len(body) != 0 {
			return fmt.Errorf("expected empty body, got %q", string(body))
		}

		return nil
	}
}

func expectEmptyBody() bodyExpectation {
	return func(contentLength int, body []byte) error {
		if contentLength != 0 {
			return fmt.Errorf("expected empty body, got content-length %d", contentLength)
		}

		if len(body) != 0 {
			return fmt.Errorf("expected empty body, got %q", string(body))
		}

		return nil
	}
}

func expect10Events() bodyExpectation {
	return func(contentLength int, body []byte) error {
		eventsCount := strings.Count(string(body), "event: ping\ndata: {\"id\":")
		if eventsCount != 10 {
			return fmt.Errorf("expected 10 events, got %d", eventsCount)
		}
		return nil
	}
}

// HealthCheck represents a single health verification
type HealthCheck struct {
	name         string
	url          string
	expectedCode int
}

// TestCase represents a single E2E test specification
type TestCase struct {
	name               string
	requestURL         string
	requestHeaders     map[string]string
	requestBody        string
	requestMethod      string
	expectedStatusCode statusCodeExpectation
	expectedBody       bodyExpectation
}

// runHealthChecks executes all health checks and returns at first failure
func runHealthChecks(healthChecks []HealthCheck) error {
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
				_, err = io.Copy(io.Discard, resp.Body)
				if err != nil {
					return err
				}
				resp.Body.Close()

				if resp.StatusCode == healthCheck.expectedCode {
					fmt.Printf("[Ok] Check successful, got status code %d\n", resp.StatusCode)
					break
				}

				if healthCheck.expectedCode == configCheckStatusCode {
					return fmt.Errorf("configs check failed, got status code %d, expected %d. Please check configs used", resp.StatusCode, healthCheck.expectedCode)
				}

				fmt.Printf("[Wait] Unexpected status code %d\n", resp.StatusCode)
			}
			timeout--
			if timeout == 0 {
				if err != nil {
					return fmt.Errorf("timeout waiting for response from %s, make sure the server is running. Last request error: %w", healthCheck.url, err)
				}

				return fmt.Errorf("timeout waiting for response from %s, unexpected status code", healthCheck.url)
			}
		}
	}
	return nil
}

// runTests executes all provided tests and validates expectations
func runTests(tests []TestCase) error {
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
		for k, v := range test.requestHeaders {
			req.Header.Add(k, v)
		}
		req.Header.Add("coraza-e2e", "ok")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("could not do http request: %v", err)
		}

		respBody, errReadRespBody := io.ReadAll(resp.Body)
		resp.Body.Close()

		if test.expectedStatusCode != nil {
			if err := test.expectedStatusCode(resp.StatusCode); err != nil {
				return err
			}

			fmt.Printf("[Ok] Got expected status code %d\n", resp.StatusCode)
		}

		if test.expectedBody != nil {
			// Some servers might abort the request before sending the body (E.g. triggering a phase 3 rule with deny action)
			// Therefore, we check if we properly read the body only if we expect a body to be received.
			if errReadRespBody != nil {
				return fmt.Errorf("could not read response body: %v", err)
			}

			if err := test.expectedBody(len(respBody), respBody); err != nil {
				return err
			}

			fmt.Print("[Ok] Got expected response body\n")
		}
	}
	return nil
}

func Run(cfg Config) error {
	healthURL := setHTTPSchemeIfMissing(cfg.HttpbinEntrypoint) + "/status/200"
	baseProxyURL := setHTTPSchemeIfMissing(cfg.ProxiedEntrypoint)
	echoProxiedURL := setHTTPSchemeIfMissing(baseProxyURL) + "/anything"

	healthChecks := []HealthCheck{
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

	tests := []TestCase{
		{
			name:               "Legit request",
			requestURL:         baseProxyURL + "?arg=arg_1",
			requestMethod:      "GET",
			expectedStatusCode: expectStatusCode(200),
		},
		{
			name:               "Denied request by URL",
			requestURL:         baseProxyURL + "/admin",
			requestMethod:      "GET",
			expectedStatusCode: expectStatusCode(403),
			expectedBody:       expectEmptyBody(),
		},
		{
			name:          "Legit request with legit body",
			requestURL:    echoProxiedURL,
			requestMethod: "POST",
			// When sending a POST request, the "application/x-www-form-urlencoded" content-type header is needed
			// being the only content-type for which by default Coraza enforces the request body processing.
			// See https://github.com/corazawaf/coraza/issues/438
			requestHeaders:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestBody:        "This is a legit payload",
			expectedStatusCode: expectStatusCode(200),
		},
		{
			name:               "Denied request with a malicious request body",
			requestURL:         echoProxiedURL,
			requestMethod:      "POST",
			requestHeaders:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestBody:        "maliciouspayload",
			expectedStatusCode: expectStatusCode(403),
		},
		{
			name:               "Denied request with a malicious response header",
			requestURL:         baseProxyURL + "/response-headers?pass=leak",
			requestMethod:      "GET",
			expectedStatusCode: expectStatusCode(403),
		},
		{
			name:               "Denied request with a malicious response body",
			requestURL:         echoProxiedURL,
			requestMethod:      "POST",
			requestHeaders:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestBody:        "responsebodycode",
			expectedBody:       expectEmptyOrNulledBody(cfg.NulledBody),
			expectedStatusCode: expectNulledBodyStatusCode(cfg.NulledBody, 403, 200),
		},
		{
			name:               "Denied request with XSS query parameters",
			requestURL:         echoProxiedURL + "?arg=<script>alert(0)</script>",
			requestMethod:      "GET",
			expectedStatusCode: expectStatusCode(403),
		},
		{
			name:               "Denied request with SQLi query parameters",
			requestURL:         echoProxiedURL,
			requestMethod:      "POST",
			requestHeaders:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestBody:        "1%27%20ORDER%20BY%203--%2B",
			expectedStatusCode: expectStatusCode(403),
		},
		{
			name:       "CRS malicious UA test (913100-6)",
			requestURL: echoProxiedURL,
			requestHeaders: map[string]string{
				"User-Agent": "Grabber/0.1 (X11; U; Linux i686; en-US; rv:1.7)",
			},
			requestMethod:      "GET",
			expectedStatusCode: expectStatusCode(403),
		},
	}

	if err := runHealthChecks(healthChecks); err != nil {
		return err
	}

	if err := runTests(tests); err != nil {
		return err
	}
	return nil
}

func RunStreamedResponse(cfg Config) error {
	healthURL := setHTTPSchemeIfMissing(cfg.HttpbinEntrypoint) + "/status/200"
	baseProxyURL := setHTTPSchemeIfMissing(cfg.ProxiedEntrypoint)

	healthChecks := []HealthCheck{
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

	tests := []TestCase{
		{
			name:               "Legit response stream",
			requestURL:         baseProxyURL + "/sse?delay=1s&duration=5s&count=10",
			requestMethod:      "GET",
			expectedStatusCode: expectStatusCode(200),
			expectedBody:       expect10Events(),
		},
	}

	if err := runHealthChecks(healthChecks); err != nil {
		return err
	}

	if err := runTests(tests); err != nil {
		return err
	}
	return nil
}

func setHTTPSchemeIfMissing(rawURL string) string {
	if rawURL == "" || strings.HasPrefix(rawURL, "http") || strings.HasPrefix(rawURL, "://") {
		return rawURL
	}

	return "http://" + rawURL
}
