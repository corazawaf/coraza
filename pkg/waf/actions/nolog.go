package actions

import(
	"github.com/jptosso/coraza/pkg/models"
)

type Nolog struct {
}

func (a *Nolog) Init(r *models.Rule, data string, errors []string) () {
	r.Log = false
}

func (a *Nolog) Evaluate(r *models.Rule, tx *models.Transaction) () {
	
}

func (a *Nolog) GetType() string{
	return ""
}
