package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Status struct {}

func (a *Status) Init(r *models.Rule, b1 string, errors []string) () {
	
}

func (a *Status) Evaluate(r *models.Rule, tx *models.Transaction) () {
	
}

func (a *Status) GetType() string{
	return ""
}
