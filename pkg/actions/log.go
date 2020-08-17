package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Log struct {
}

func (a *Log) Init(r *engine.Rule, data string) []string {
	r.Log = true
	return []string{}
}

func (a *Log) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Log) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
