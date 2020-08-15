package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Drop struct {}

func (a *Drop) Init(r *engine.Rule, data string, errors []string) () {
	r.Action = "drop"
}

func (a *Drop) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
    tx.Status = 403;
    tx.Disrupted = true
    tx.DisruptiveRuleId = r.Id
}

func (a *Drop) GetType() string{
	return "disruptive"
}
