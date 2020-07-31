package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Rev struct {
}

func (a *Rev) Init(r *engine.Rule, data string, errors []string) () {
	r.Rev = data
}

func (a *Rev) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Rev) GetType() string{
	return "metadata"
}
