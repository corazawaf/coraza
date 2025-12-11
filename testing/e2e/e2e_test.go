// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo

package e2e_test

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mccutchen/go-httpbin/v2/httpbin"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/http/e2e"
)

func TestE2e(t *testing.T) {
	conf := coraza.NewWAFConfig()

	conf = conf.
		WithDirectives(e2e.Directives)

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

func TestE2eStreamedResponse(t *testing.T) {
	conf := coraza.NewWAFConfig()

	conf = conf.
		WithDirectives(e2e.DirectivesStreamedResponse)

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

	err = e2e.RunStreamedResponse(e2e.Config{
		NulledBody:        false,
		ProxiedEntrypoint: s.URL,
		HttpbinEntrypoint: s.URL,
	})
	if err != nil {
		t.Fatalf("e2e tests failed: %v", err)
	}
}
