package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Allow struct {

}
func (a *Allow) Init(r *engine.Rule, b1 string, errors []string) () {
	// Does not require initializer
}

func (a *Allow) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Disrupted = false
}

func (a *Allow) GetType() string{
	return "disruptive"
}