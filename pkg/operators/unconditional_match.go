package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type UnconditionalMatch struct{}

func (o *UnconditionalMatch) Init(data string){
}

func (o *UnconditionalMatch) Evaluate(tx *engine.Transaction, value string) bool{
	return true
}