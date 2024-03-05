// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/corazawaf/coraza/v3/http/e2e"
)

// Flags:
// --nulled-body: Interruptions at response body phase are allowed to return 200 (Instead of 403), but with a body full of null bytes. Defaults to "false".
// --proxy-hostport: Proxy endpoint used to perform requests. Defaults to "localhost:8080".
// --httpbin-hostport: Upstream httpbin endpoint, used for health checking reasons. Defaults to "localhost:8081".

// A dedicated set of directives is expected to be loaded for e2e testing. Refer to the `Directives` const in http/e2e.go.

func main() {
	// Initialize variables
	var (
		nulledBody      = flag.Bool("nulled-body", false, "Accept a body filled of empty bytes as an enforced disruptive action. Default: false")
		proxyHostport   = flag.String("proxy-hostport", "localhost:8080", "Configures the URL in which the proxy is running. Default: \"localhost:8080\"")
		httpbinHostport = flag.String("httpbin-hostport", "localhost:8081", "Configures the URL in which httpbin is running. Default: \"localhost:8081\"")
	)
	flag.Parse()

	err := e2e.Run(e2e.Config{
		NulledBody:        *nulledBody,
		ProxiedEntrypoint: *proxyHostport,
		HttpbinEntrypoint: *httpbinHostport,
	})

	if err != nil {
		fmt.Printf("[Fail] %s\n", err)
		os.Exit(1)
	}
}
