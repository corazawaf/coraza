package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Chain struct {}

func (a *Chain) Init(r *engine.Rule, b1 string, errors []string) () {
	r.HasChain = true
}

func (a *Chain) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Chain) GetType() string{
	return "flow"
}
