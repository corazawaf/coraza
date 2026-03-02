package experimental

import (
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// wafConfigWithRuleObserver is the private capability interface
type wafConfigWithRuleObserver interface {
	WithRuleObserver(func(rule types.RuleMetadata)) coraza.WAFConfig
}

// WAFConfigWithRuleObserver applies a rule observer if supported.
func WAFConfigWithRuleObserver(
	cfg coraza.WAFConfig,
	observer func(rule types.RuleMetadata),
) coraza.WAFConfig {
	if c, ok := cfg.(wafConfigWithRuleObserver); ok {
		return c.WithRuleObserver(observer)
	}
	return cfg
}
