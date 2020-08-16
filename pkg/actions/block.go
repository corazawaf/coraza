package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Block struct {}

func (a *Block) Init(r *engine.Rule, b1 string, errors []string) () {
	r.Action = "block"
}

func (a *Block) Evaluate(r *engine.Rule, tx *engine.Transaction) () {

}

func (a *Block) GetType() string{
	return "disruptive"
}
