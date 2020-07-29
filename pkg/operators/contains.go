package operators

import(
	"strings"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Contains struct{
	data string
}

func (o *Contains) Init(data string){
	o.data = data
}

func (o *Contains) Evaluate(tx *engine.Transaction, value string) bool{
	return strings.Contains(value, o.data)
}