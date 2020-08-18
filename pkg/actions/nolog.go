package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Nolog struct {
}

func (a *Nolog) Init(r *engine.Rule, data string) string {
	r.Log = false
	return ""
}

func (a *Nolog) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Nolog) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
