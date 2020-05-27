package actions

import(
	"github.com/jptosso/coraza/pkg/models"
)

type MultiMatch struct {
}

func (a *MultiMatch) Init(r *models.Rule, data string, errors []string) () {
	r.MultiMatch = true
}

func (a *MultiMatch) Evaluate(r *models.Rule, tx *models.Transaction) () {

}

func (a *MultiMatch) GetType() string{
	return "nd"
}
