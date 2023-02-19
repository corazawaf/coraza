// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"testing"

	"github.com/corazawaf/coraza/v3/plugins"
	"github.com/corazawaf/coraza/v3/types"
)

func TestConfigRulesImmutable(t *testing.T) {
	// Add enough directives so there is enough slice capacity to reuse the array for next append.
	c := NewWAFConfig().
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRuleEngine On")

	c1 := c.WithDirectives("SecRequestBodyAccess On")

	waf1, err := NewWAF(c1)
	if err != nil {
		t.Fatal(err)
	}

	if !waf1.(wafWrapper).waf.RequestBodyAccess {
		t.Errorf("waf1: expected request body access to be enabled")
	}

	if waf1.(wafWrapper).waf.ResponseBodyAccess {
		t.Errorf("waf1: expected response body access to be disabled")
	}

	c2 := c.WithDirectives("SecResponseBodyAccess On")

	waf2, err := NewWAF(c2)
	if err != nil {
		t.Fatal(err)
	}

	if waf2.(wafWrapper).waf.RequestBodyAccess {
		t.Errorf("waf1: expected request body access to be disabled")
	}

	if !waf2.(wafWrapper).waf.ResponseBodyAccess {
		t.Errorf("waf1: expected response body access to be enabled")
	}

	// c1 should not have been affected
	waf1, err = NewWAF(c1)
	if err != nil {
		t.Fatal(err)
	}

	if !waf1.(wafWrapper).waf.RequestBodyAccess {
		t.Errorf("waf1: expected request body access to be enabled")
	}

	if waf1.(wafWrapper).waf.ResponseBodyAccess {
		t.Errorf("waf1: expected response body access to be disabled")
	}
}

func TestConfigSetters(t *testing.T) {
	changed := false
	c := func(_ types.MatchedRule) {
		changed = true
	}
	cfg := NewWAFConfig().
		WithRequestBodyAccess().
		WithResponseBodyAccess().
		WithErrorCallback(c).
		WithRequestBodyLimit(200).
		WithRequestBodyInMemoryLimit(100).
		WithResponseBodyMimeTypes([]string{"text/html"}).
		WithDirectives(`
		SecRule REQUEST_URI "@unconditionalMatch" "phase:1,id:1,log,msg:'ok'"
		SecRule RESPONSE_BODY "aaa" "phase:4,id:40,log,msg:'ok'"
		`)
	alCfg := NewAuditLogConfig()
	waf, err := NewWAF(cfg.WithAuditLog(alCfg))
	if err != nil {
		t.Fatal(err)
	}
	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.AddResponseHeader("Content-Type", "text/html")
	tx.ProcessResponseHeaders(200, "http/1.1")
	if _, _, err := tx.WriteResponseBody([]byte("aaa")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Errorf("error callback not called")
	}
	if !tx.IsResponseBodyProcessable() {
		t.Errorf("response body should be processable")
	}
	expectedMatches := []int{1, 40}
	for _, id := range expectedMatches {
		ok := false
		for _, m := range tx.MatchedRules() {
			if m.Rule().ID() == id {
				ok = true
			}
		}
		if !ok {
			t.Errorf("expected rule %d to match", id)
		}
	}
}

func TestConfigLogger(t *testing.T) {
	logger, err := plugins.GetAuditLogWriter("concurrent")
	if err != nil {
		t.Fatal(err)
	}
	logCfg := NewAuditLogConfig().
		LogRelevantOnly().
		WithLogger(logger).
		WithParts([]types.AuditLogPart("abcdedf"))
	cfg := NewWAFConfig().WithAuditLog(logCfg)
	waf, err := NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w := waf.(wafWrapper)
	// TODO(jptosso): this is not working, but there is a comment in the code
	/*
		if w.waf.AuditEngine != types.AuditEngineRelevantOnly {
			t.Errorf("expected audit engine to be relevant only")
		}
	*/
	if w.waf.AuditLogWriter == nil {
		t.Errorf("expected audit log writer to be set")
	}
	if w.waf.AuditLogParts == nil {
		t.Errorf("expected audit log parts to be set")
	}
}
