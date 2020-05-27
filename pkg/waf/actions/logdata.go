package actions

import(
	"github.com/jptosso/coraza/pkg/models"
)

type Logdata struct {
	data string
}

func (a *Logdata) Init(r *models.Rule, data string, errors []string) () {
	a.data = data
}

func (a *Logdata) Evaluate(r *models.Rule, tx *models.Transaction) () {
	tx.Logdata = append(tx.Logdata, tx.MacroExpansion(a.data))
}

func (a *Logdata) GetType() string{
	return ""
}
