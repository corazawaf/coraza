package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strings"
)

type SkipAfter struct {
	data string
}

//NOT IMPLEMENTED
func (a *SkipAfter) Init(r *engine.Rule, data string) []string {
	a.data = strings.Trim(data, `"`)
	return []string{}
}

func (a *SkipAfter) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.SkipAfter = a.data
}

func (a *SkipAfter) GetType() int{
	return engine.ACTION_TYPE_FLOW
}
