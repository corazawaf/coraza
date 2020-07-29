package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type FuzzyHash struct{
	data string
}

func (o *FuzzyHash) Init(data string){
	o.data = data
}

func (o *FuzzyHash) Evaluate(tx *engine.Transaction, value string) bool{
	return false
}