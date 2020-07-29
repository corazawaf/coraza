package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Deny struct {}

func (a *Deny) Init(r *engine.Rule, data string, errors []string) () {
	r.Action = "deny"
}

func (a *Deny) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
    if tx.Status == 200 {
        tx.Status = 403;
        tx.DisruptiveRuleId = r.Id
        tx.Disrupted = true
    }
}

func (a *Deny) GetType() string{
	return "disruptive"
}
