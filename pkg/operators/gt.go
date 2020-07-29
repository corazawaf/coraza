package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strconv"
)

type Gt struct{
	data string
}

func (o *Gt) Init(data string){
	o.data = data
}

func (o *Gt) Evaluate(tx *engine.Transaction, value string) bool{
	v, err := strconv.Atoi(value)
	if  err != nil{
		return false
	}
	data := tx.MacroExpansion(o.data)
	k, err := strconv.Atoi(data)
	if err != nil{
		return false
	}
	return k < v
}