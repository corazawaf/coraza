package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Pass struct {
}

func (a *Pass) Init(r *engine.Rule, data string, errors []string) () {
	r.Action = "pass"
}

func (a *Pass) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
}

func (a *Pass) GetType() string{
	return "disruptive"
}
