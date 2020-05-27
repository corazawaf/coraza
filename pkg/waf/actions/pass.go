package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Pass struct {
}

func (a *Pass) Init(r *models.Rule, data string, errors []string) () {
	r.Action = "pass"
}

func (a *Pass) Evaluate(r *models.Rule, tx *models.Transaction) () {
}

func (a *Pass) GetType() string{
	return "disruptive"
}
