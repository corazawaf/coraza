package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Eq struct{
	data string
}

func (o *Eq) Init(data string){
	o.data = data
}

func (o *Eq) Evaluate(tx *engine.Transaction, value string) bool{
	return o.data == value
}