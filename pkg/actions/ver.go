package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Ver struct {
}

func (a *Ver) Init(r *engine.Rule, data string, errors []string) () {
	r.Version = data
}

func (a *Ver) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Ver) GetType() string{
	return "metadata"
}
