package actions

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Phase struct {}

func (a *Phase) Init(r *engine.Rule, data string, errors []string) () {
	i, _ := strconv.Atoi(data)
	r.Phase = int(i)
}

func (a *Phase) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Phase) GetType() string{
	return "metadata"
}
