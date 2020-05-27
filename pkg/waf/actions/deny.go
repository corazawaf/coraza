package actions

import(
	"github.com/jptosso/coraza/pkg/models"
)

type Deny struct {}

func (a *Deny) Init(r *models.Rule, data string, errors []string) () {
	r.Action = "deny"
}

func (a *Deny) Evaluate(r *models.Rule, tx *models.Transaction) () {
    if tx.Status == 200 {
        tx.Status = 403;
        tx.DisruptiveRuleId = r.Id
        tx.Disrupted = true
    }
}

func (a *Deny) GetType() string{
	return "disruptive"
}
