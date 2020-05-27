package actions

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Log struct {
}

func (a *Log) Init(r *models.Rule, data string, errors []string) () {
	r.Log = true
}

func (a *Log) Evaluate(r *models.Rule, tx *models.Transaction) () {
	
}

func (a *Log) GetType() string{
	return ""
}
