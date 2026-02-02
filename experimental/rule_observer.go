package experimental

import (
	"github.com/corazawaf/coraza/v3/types"
)

// wafConfigWithRuleObserver is the private capability interface
type wafConfigWithRuleObserver interface {
	WithRuleObserver(func(rule types.RuleMetadata)) any
}

// WAFConfigWithRuleObserver applies a rule observer if supported.
func WAFConfigWithRuleObserver(
	cfg any,
	observer func(rule types.RuleMetadata),
) any {
	if c, ok := cfg.(wafConfigWithRuleObserver); ok {
		return c.WithRuleObserver(observer)
	}
	return cfg
}
