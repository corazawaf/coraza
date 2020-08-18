package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Severity struct {
}

func (a *Severity) Init(r *engine.Rule, data string) string {
	r.Severity = data
	return ""
}

func (a *Severity) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Severity) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
