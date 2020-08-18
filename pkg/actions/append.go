package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Append struct {
	Data string
}

func (a *Append) Init(r *engine.Rule, data string) string {
	a.Data = data
	return ""
}

func (a *Append) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	rb := tx.Collections["tx"].Get("response_body")
	if len(rb) > 0{
		tx.Collections["tx"].Set("response_body", []string{rb[0]+a.Data})
	}
}

func (a *Append) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
