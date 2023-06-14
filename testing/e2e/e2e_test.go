// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo
// +build !tinygo

package e2e_test

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	e2e "github.com/corazawaf/coraza/v3/http/e2e/pkg"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
)

func TestE2e(t *testing.T) {
	conf := coraza.NewWAFConfig()

	customE2eDirectives := `
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
	SecRule ARGS_NAMES|ARGS|XML:/* "@detectXSS" "id:9411,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,log,deny"
	SecRule ARGS_NAMES|ARGS|XML:/* "@detectSQLi" "id:9421,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,multiMatch,log,deny"
	SecRule REQUEST_HEADERS:User-Agent "@pm grabber masscan havij" "id:9131,phase:1,t:none,log,deny"
`
	conf = conf.
		WithDirectives(customE2eDirectives)

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		t.Fatal(err)
	}

	httpbin := httpbin.New()

	mux := http.NewServeMux()
	mux.Handle("/status/200", httpbin) // Health check
	mux.Handle("/", txhttp.WrapHandler(waf, httpbin))

	// Create the server with the WAF and the reverse proxy.
	s := httptest.NewServer(mux)
	defer s.Close()

	err = e2e.Run(e2e.Config{
		NulledBody:        false,
		ProxiedEntrypoint: s.URL,
		HttpbinEntrypoint: s.URL,
	})
	if err != nil {
		t.Fatalf("e2e tests failed: %v", err)
	}
}
