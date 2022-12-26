package coraza

import (
	"testing"
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
