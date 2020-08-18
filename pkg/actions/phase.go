package actions

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Phase struct {}

func (a *Phase) Init(r *engine.Rule, data string) string {
	i, _ := strconv.Atoi(data)
	r.Phase = int(i)
	return ""
}

func (a *Phase) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Phase) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
