package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Block struct {}

func (a *Block) Init(r *models.Rule, b1 string, errors []string) () {
	r.Action = "block"
}

func (a *Block) Evaluate(r *models.Rule, tx *models.Transaction) () {
	if tx.DefaultAction != "pass"{
		tx.Status = 403
		tx.Disrupted = true
		tx.DisruptiveRuleId = r.Id
	}
}

func (a *Block) GetType() string{
	return "disruptive"
}
