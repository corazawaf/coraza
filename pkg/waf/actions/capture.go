package actions

import(
	"github.com/jptosso/coraza/pkg/models"
)


type Capture struct {}

func (a *Capture) Init(r *models.Rule, b1 string, errors []string) () {
	r.Capture = true
}

func (a *Capture) Evaluate(r *models.Rule, tx *models.Transaction) () {
	tx.Capture = true
}

func (a *Capture) GetType() string{
	return ""
}
