package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Allow struct {

}
func (a *Allow) Init(r *models.Rule, b1 string, errors []string) () {
	
}

func (a *Allow) Evaluate(r *models.Rule, tx *models.Transaction) () {
	tx.Disrupted = false
}

func (a *Allow) GetType() string{
	return "disruptive"
}