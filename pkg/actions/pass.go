package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Pass struct {
}

func (a *Pass) Init(r *engine.Rule, data string) []string {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_PASS
	return []string{}
}

func (a *Pass) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Pass) GetType() int{
	return engine.ACTION_TYPE_DISRUPTIVE
}
