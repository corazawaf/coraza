package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type NoMatch struct{
}

func (o *NoMatch) Init(data string){
	// No need to init
}

func (o *NoMatch) Evaluate(tx *engine.Transaction, value string) bool{
	return false
}
