package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Tag struct {
}

func (a *Tag) Init(r *engine.Rule, data string) []string {
	r.Tags = append(r.Tags, data[1:len(data)-1])
	return []string{}
}

func (a *Tag) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Tag) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
