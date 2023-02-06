// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

func TestRecommendedDirectives(t *testing.T) {
	c := NewWAFConfig().
		WithRecommendedDirectives()

	waf, err := NewWAF(c)
	if err != nil {
		t.Fatal(err)
	}

	if want, have := types.RuleEngineDetectionOnly, waf.(wafWrapper).waf.RuleEngine; want != have {
		t.Errorf("unexpected rule engine, want %d, have %d", want, have)
	}
}

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
