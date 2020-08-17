package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Msg struct {
}

func (a *Msg) Init(r *engine.Rule, data string) []string {
	r.Msg = data
	return []string{}
}

func (a *Msg) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Msg) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
