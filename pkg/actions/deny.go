package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Deny struct {}

func (a *Deny) Init(r *engine.Rule, data string) []string {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_DENY
	return []string{}
}

func (a *Deny) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
    tx.Status = 403;
    tx.DisruptiveRuleId = r.Id
    tx.Disrupted = true
}

func (a *Deny) GetType() int{
	return engine.ACTION_TYPE_DISRUPTIVE
}
