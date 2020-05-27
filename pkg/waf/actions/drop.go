package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Drop struct {}

func (a *Drop) Init(r *models.Rule, data string, errors []string) () {
	r.Action = "drop"
}

func (a *Drop) Evaluate(r *models.Rule, tx *models.Transaction) () {
    if tx.Status == 200 {
        tx.Status = 403;
        tx.Disrupted = true
        tx.DisruptiveRuleId = r.Id
    }
}

func (a *Drop) GetType() string{
	return "disruptive"
}
