package operators

import(
	"strings"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type EndsWith struct{
	data string
}

func (o *EndsWith) Init(data string){
	o.data = data
}

func (o *EndsWith) Evaluate(tx *engine.Transaction, value string) bool{
	return strings.HasSuffix(value, o.data)
}