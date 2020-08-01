package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Log struct {
}

func (a *Log) Init(r *engine.Rule, data string, errors []string) () {
	r.Log = true
}

func (a *Log) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Log) GetType() string{
	return ""
}
