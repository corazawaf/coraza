package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Maturity struct {
}

func (a *Maturity) Init(r *engine.Rule, data string) string {
	r.Maturity = data
	return ""
}

func (a *Maturity) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Maturity) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
