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

// Expected Coraza configs:
/*
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
*/

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
