package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Drop struct {}

func (a *Drop) Init(r *engine.Rule, data string) []string {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_DROP
	return []string{}
}

func (a *Drop) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
    tx.Status = 403;
    tx.Disrupted = true
    tx.DisruptiveRuleId = r.Id
}

func (a *Drop) GetType() int{
	return engine.ACTION_TYPE_DISRUPTIVE
}
