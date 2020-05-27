package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Append struct {
	Data string
}

func (a *Append) Init(r *models.Rule, data string, errors []string) () {
	a.Data = data
}

func (a *Append) Evaluate(r *models.Rule, tx *models.Transaction) () {
	rb := tx.Collections["tx"].Get("response_body")
	if len(rb) > 0{
		tx.Collections["tx"].Set("response_body", []string{rb[0]+a.Data})
	}
}

func (a *Append) GetType() string{
	return "metadata"
}
