package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Status struct {}

func (a *Status) Init(r *engine.Rule, b1 string, errors []string) () {
	
}

func (a *Status) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	
}

func (a *Status) GetType() string{
	return ""
}
