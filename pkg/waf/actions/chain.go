package actions

import(
	"github.com/jptosso/coraza/pkg/models"
)

type Chain struct {}

func (a *Chain) Init(r *models.Rule, b1 string, errors []string) () {
	r.HasChain = true
}

func (a *Chain) Evaluate(r *models.Rule, tx *models.Transaction) () {
	
}

func (a *Chain) GetType() string{
	return "flow"
}
