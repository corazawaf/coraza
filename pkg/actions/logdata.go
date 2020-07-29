package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Logdata struct {
	data string
}

func (a *Logdata) Init(r *engine.Rule, data string, errors []string) () {
	a.data = data
}

func (a *Logdata) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Logdata = append(tx.Logdata, tx.MacroExpansion(a.data))
}

func (a *Logdata) GetType() string{
	return ""
}
