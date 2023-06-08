// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo
// +build !tinygo

package e2e_test

import (
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	e2e "github.com/corazawaf/coraza/v3/http/e2e/pkg"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
)

func TestE2e(t *testing.T) {
	conf := coraza.NewWAFConfig()

	recommended, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}

	customE2eDirectives := `
	SecRuleEngine On
	# Custom rule for Coraza config check (ensuring that these configs are used)
	SecRule &REQUEST_HEADERS:coraza-e2e "@eq 0" "id:100,phase:1,deny,status:424,msg:'Coraza E2E - Missing header'"
	# Custom rules for e2e testing
	SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny"
	SecRule REQUEST_BODY "@rx maliciouspayload" "id:102,phase:2,t:lowercase,deny"
	SecRule RESPONSE_HEADERS:pass "@rx leak" "id:103,phase:3,t:lowercase,deny"
	SecRule RESPONSE_BODY "@contains responsebodycode" "id:104,phase:4,t:lowercase,deny"
`
	conf = conf.
		WithRootFS(coreruleset.FS).
		WithDirectives(string(recommended)).
		WithDirectives("Include @crs-setup.conf.example").
		WithDirectives("Include @owasp_crs/*.conf").
		WithDirectives(customE2eDirectives)

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		t.Fatal(err)
	}

	httpbinServer := httptest.NewServer(httpbin.New())
	defer httpbinServer.Close()

	httpbinURL, _ := url.Parse(httpbinServer.URL)
	proxy := httputil.NewSingleHostReverseProxy(httpbinURL)

	// Create the server with the WAF and the reverse proxy.
	s := httptest.NewServer(txhttp.WrapHandler(waf, proxy))
	sURL, _ := url.Parse(s.URL)
	err = e2e.Run(e2e.Config{
		NulledBody:      false,
		ProxyHostport:   sURL.Host,
		HttpbinHostport: httpbinURL.Host,
	})
	if err != nil {
		t.Fatalf("e2e tests failed: %v", err)
	}
}
