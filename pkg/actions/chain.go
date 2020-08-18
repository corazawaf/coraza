package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Chain struct {}

func (a *Chain) Init(r *engine.Rule, b1 string) string {
	r.HasChain = true
	return ""
}

func (a *Chain) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Chain) GetType() int{
	return engine.ACTION_TYPE_FLOW
}
