package experimental

import (
	"reflect"

	"github.com/corazawaf/coraza/v3/types"
)

// WAFConfigWithRuleObserver applies a rule observer if supported.
func WAFConfigWithRuleObserver(
	cfg any,
	observer func(rule types.RuleMetadata),
) any {
	v := reflect.ValueOf(cfg)

	m := v.MethodByName("WithRuleObserver")
	if !m.IsValid() {
		return cfg
	}

	t := m.Type()
	if t.NumIn() != 1 || t.In(0) != reflect.TypeOf(observer) {
		return cfg
	}

	out := m.Call([]reflect.Value{
		reflect.ValueOf(observer),
	})

	if len(out) == 1 {
		return out[0].Interface()
	}

	return cfg
}
