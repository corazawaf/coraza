package e2e

// Package e2e provides end-to-end testing routine for the Coraza WAF connectors.
// It includes configurations and functions to run tests against a proxy
// endpoint and an upstream [httpbingo](https://httpbingo.org/) service, validating
// the WAF's behavior under various scenarios.
//
// Important: The proxy under test is expected to have Coraza WAF integrated and configured
// according to the provided `Directives` constant in this package.
//
// As a library, it exposes the Run function which accepts a Config struct
// to customize the test parameters:
//
// 	cfg := e2e.Config{
// 		NulledBody:        false,
// 		ProxiedEntrypoint: "localhost:8080",
// 		HttpbinEntrypoint: "localhost:8081",
// 	}
//
// 	err := e2e.Run(cfg)
// 	if err != nil {
// 		log.Fatalf("E2E tests failed: %v", err)
// 	}
//
// It can be also used via the provided CLI tool located at http/e2e/cmd/httpe2e
// which accepts flags to configure the test parameters.
//
// Example CLI usage:
// 	httpe2e --proxy-hostport="localhost:8080" --httpbin-hostport="localhost:8081" --nulled-body=false
