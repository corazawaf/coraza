// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// These benchmarks don't currently compile with TinyGo
//go:build !tinygo
// +build !tinygo

package e2e_test

import (
	"bufio"
	b64 "encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	e2e "github.com/corazawaf/coraza/v3/http/e2e/pkg"
	"github.com/corazawaf/coraza/v3/types"
)

func TestE2e(t *testing.T) {
	conf := coraza.NewWAFConfig()

	recommended, err := os.ReadFile(filepath.Join("..", "..", "coraza.conf-recommended"))
	if err != nil {
		t.Fatal(err)
	}

	customTestingConfig := `
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
		WithDirectives(customTestingConfig)

	errorPath := filepath.Join(t.TempDir(), "e2e_error.log")
	errorFile, err := os.Create(errorPath)
	if err != nil {
		t.Fatalf("failed to create error log: %v", err)
	}
	errorWriter := bufio.NewWriter(errorFile)
	conf = conf.WithErrorCallback(func(rule types.MatchedRule) {
		msg := rule.ErrorLog()
		if _, err := io.WriteString(errorWriter, msg); err != nil {
			t.Fatal(err)
		}
		if err := errorWriter.Flush(); err != nil {
			t.Fatal(err)
		}
	})

	waf, err := coraza.NewWAF(conf)
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(txhttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		w.Header().Set("Content-Type", "text/plain")
		// Emualtes httpbin behaviour
		switch {
		case r.URL.Path == "/anything":
			body, err := io.ReadAll(r.Body)
			if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
				if err != nil {
					t.Fatalf("handler can not read request body: %v", err)
				}
				urldecodedBody, err := url.QueryUnescape(string(body))
				if err != nil {
					t.Fatalf("handler can not unescape urlencoded request body: %v", err)
				}
				fmt.Fprint(w, urldecodedBody)
			} else {
				_, _ = w.Write(body)
			}

		case strings.HasPrefix(r.URL.Path, "/base64/"):
			// Emulated httpbin behaviour: /base64 endpoint write the decoded base64 into the response body
			b64Decoded, err := b64.StdEncoding.DecodeString(strings.TrimPrefix(r.URL.Path, "/base64/"))
			if err != nil {
				t.Fatalf("handler can not decode base64: %v", err)
			}
			fmt.Fprint(w, string(b64Decoded))
		case strings.HasPrefix(r.URL.Path, "/response-headers"):
			// Emulated httpbin behaviour: /response-headers endpoint
			for key, values := range r.URL.Query() {
				w.Header().Set(key, values[0])
			}
			w.WriteHeader(200)
		default:
			fmt.Fprintf(w, "Hello!")
		}
	})))
	defer s.Close()

	serverUrl := strings.TrimPrefix(s.URL, "http://")
	err = e2e.Run(e2e.Config{
		NulledBody:      false,
		ProxyHostport:   serverUrl,
		HttpbinHostport: serverUrl,
	})
	if err != nil {
		t.Fatalf("e2e tests failed: %v", err)
	}
}
