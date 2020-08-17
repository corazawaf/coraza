package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type MultiMatch struct {
}

func (a *MultiMatch) Init(r *engine.Rule, data string) []string {
	r.MultiMatch = true
	return []string{}
}

func (a *MultiMatch) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *MultiMatch) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
