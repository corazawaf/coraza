package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Auditlog struct {

}
func (a *Auditlog) Init(r *models.Rule, b1 string, errors []string) () {
	
}

func (a *Auditlog) Evaluate(r *models.Rule, tx *models.Transaction) () {
	tx.Log = true
}

func (a *Auditlog) GetType() string{
	return "nd"
}