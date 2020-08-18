package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)


type Capture struct {}

func (a *Capture) Init(r *engine.Rule, b1 string) string {
	//r.Capture = true
	return ""
}

func (a *Capture) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Capture = true
}

func (a *Capture) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
