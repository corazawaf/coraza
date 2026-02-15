// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
)

func TestConfigRulesImmutable(t *testing.T) {
	// Add enough directives so there is enough slice capacity to reuse the array for next append.
	c := NewWAFConfig().
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRuleEngine On").
		WithDirectives("SecRuleEngine On")

	c1 := c.WithDirectives("SecRequestBodyAccess On")

	waf1, err := NewWAF(c1)
	require.NoError(t, err)

	require.True(t, waf1.(wafWrapper).waf.RequestBodyAccess, "waf1: expected request body access to be enabled")
	require.False(t, waf1.(wafWrapper).waf.ResponseBodyAccess, "waf1: expected response body access to be disabled")

	c2 := c.WithDirectives("SecResponseBodyAccess On")

	waf2, err := NewWAF(c2)
	require.NoError(t, err)

	require.False(t, waf2.(wafWrapper).waf.RequestBodyAccess, "waf1: expected request body access to be disabled")
	require.True(t, waf2.(wafWrapper).waf.ResponseBodyAccess, "waf1: expected response body access to be enabled")

	// c1 should not have been affected
	waf1, err = NewWAF(c1)
	require.NoError(t, err)

	require.True(t, waf1.(wafWrapper).waf.RequestBodyAccess, "waf1: expected request body access to be enabled")
	require.False(t, waf1.(wafWrapper).waf.ResponseBodyAccess, "waf1: expected response body access to be disabled")
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
	waf, err := NewWAF(cfg)
	require.NoError(t, err)

	tx := waf.NewTransaction()
	tx.ProcessRequestHeaders()
	tx.AddResponseHeader("Content-Type", "text/html")
	tx.ProcessResponseHeaders(200, "http/1.1")
	_, _, err = tx.WriteResponseBody([]byte("aaa"))
	require.NoError(t, err)

	_, err = tx.ProcessResponseBody()
	require.NoError(t, err)

	require.True(t, changed, "error callback not called")
	require.True(t, tx.IsResponseBodyProcessable(), "response body should be processable")
	expectedMatches := []int{1, 40}
	for _, id := range expectedMatches {
		found := false
		for _, m := range tx.MatchedRules() {
			if m.Rule().ID() == id {
				found = true
				break
			}
		}
		require.True(t, found, "expected rule %d to match", id)
	}
}
