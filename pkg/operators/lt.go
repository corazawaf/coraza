package operators

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Lt struct{
	data int
}

func (o *Lt) Init(data string){
	k, _ := strconv.Atoi(data)
	o.data = k
}

func (o *Lt) Evaluate(tx *engine.Transaction, value string) bool{
	v, err := strconv.Atoi(value)
	if err != nil {
		//retornamos false?
		return false
	}
	return o.data > v
}
