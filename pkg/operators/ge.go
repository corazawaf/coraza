package operators

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

//TODO macro expansion
type Ge struct{
	data int
}

func (o *Ge) Init(data string){
	k, _ := strconv.Atoi(data)
	o.data = k
}

func (o *Ge) Evaluate(tx *engine.Transaction, value string) bool{
	v, err := strconv.Atoi(value)
	if  err != nil{
		return false
	}
	return v >= o.data
}