package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Tag struct {
}

func (a *Tag) Init(r *engine.Rule, data string, errors []string) () {
	r.Tags = append(r.Tags, data[1:len(data)-1])
}

func (a *Tag) Evaluate(r *engine.Rule, tx *engine.Transaction) () {

}

func (a *Tag) GetType() string{
	return "metadata"
}
