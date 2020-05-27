package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Ver struct {
}

func (a *Ver) Init(r *models.Rule, data string, errors []string) () {
	r.Version = data
}

func (a *Ver) Evaluate(r *models.Rule, tx *models.Transaction) () {

}

func (a *Ver) GetType() string{
	return "metadata"
}
