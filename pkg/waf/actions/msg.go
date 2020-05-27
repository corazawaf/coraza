package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Msg struct {
}

func (a *Msg) Init(r *models.Rule, data string, errors []string) () {
	r.Msg = data
}

func (a *Msg) Evaluate(r *models.Rule, tx *models.Transaction) () {

}

func (a *Msg) GetType() string{
	return "metadata"
}
