package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Block struct {}

func (a *Block) Init(r *engine.Rule, b1 string) []string {
	r.DisruptiveAction = engine.ACTION_DISRUPTIVE_BLOCK
	return []string{}
}

func (a *Block) Evaluate(r *engine.Rule, tx *engine.Transaction) () {

}

func (a *Block) GetType() int{
	return engine.ACTION_TYPE_DISRUPTIVE
}
