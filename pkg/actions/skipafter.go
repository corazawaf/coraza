package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strings"
)

type SkipAfter struct {
	data string
}

//NOT IMPLEMENTED
func (a *SkipAfter) Init(r *engine.Rule, data string, errors []string) () {
	a.data = strings.Trim(data, `"`)
}

func (a *SkipAfter) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.SkipAfter = a.data
}

func (a *SkipAfter) GetType() string{
	return ""
}
