package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Nolog struct {
}

func (a *Nolog) Init(r *engine.Rule, data string, errors []string) () {
	r.Log = false
}

func (a *Nolog) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Nolog) GetType() string{
	return ""
}
