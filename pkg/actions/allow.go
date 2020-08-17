package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Allow struct {

}

func (a *Allow) Init(r *engine.Rule, b1 string) []string {
	// Does not require initializer
	return []string{}
}

func (a *Allow) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Disrupted = false
}

func (a *Allow) GetType() int{
	return engine.ACTION_TYPE_DISRUPTIVE
}