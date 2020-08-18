package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Rev struct {
}

func (a *Rev) Init(r *engine.Rule, data string) string {
	r.Rev = data
	return ""
}

func (a *Rev) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Rev) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
