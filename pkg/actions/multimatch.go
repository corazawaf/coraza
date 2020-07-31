package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type MultiMatch struct {
}

func (a *MultiMatch) Init(r *engine.Rule, data string, errors []string) () {
	r.MultiMatch = true
}

func (a *MultiMatch) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *MultiMatch) GetType() string{
	return "nd"
}
