package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Noauditlog struct {
}

func (a *Noauditlog) Init(r *models.Rule, data string, errors []string) () {

}

func (a *Noauditlog) Evaluate(r *models.Rule, tx *models.Transaction) () {
	tx.AuditLog = false
}

func (a *Noauditlog) GetType() string{
	return ""
}
