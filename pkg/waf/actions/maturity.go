package actions

import(
	"github.com/jptosso/coraza/pkg/models"
)

type Maturity struct {
}

func (a *Maturity) Init(r *models.Rule, data string, errors []string) () {
	r.Maturity = data
}

func (a *Maturity) Evaluate(r *models.Rule, tx *models.Transaction) () {

}

func (a *Maturity) GetType() string{
	return "metadata"
}
