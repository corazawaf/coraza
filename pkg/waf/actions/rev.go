package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Rev struct {
}

func (a *Rev) Init(r *models.Rule, data string, errors []string) () {
	r.Rev = data
}

func (a *Rev) Evaluate(r *models.Rule, tx *models.Transaction) () {

}

func (a *Rev) GetType() string{
	return "metadata"
}
