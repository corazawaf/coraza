package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Msg struct {
}

func (a *Msg) Init(r *engine.Rule, data string, errors []string) () {
	r.Msg = data
}

func (a *Msg) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Msg) GetType() string{
	return "metadata"
}
