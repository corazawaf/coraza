package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Severity struct {
}

func (a *Severity) Init(r *models.Rule, data string, errors []string) () {
	r.Severity = data
}

func (a *Severity) Evaluate(r *models.Rule, tx *models.Transaction) () {

}

func (a *Severity) GetType() string{
	return "metadata"
}
