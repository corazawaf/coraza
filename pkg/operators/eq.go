package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strconv"
)

type Eq struct{
	data string
}

func (o *Eq) Init(data string){
	o.data = data
}

func (o *Eq) Evaluate(tx *engine.Transaction, value string) bool{
	d1, err := strconv.Atoi(tx.MacroExpansion(o.data))
	if err != nil{
		d1 = 0
	}
	d2, err := strconv.Atoi(value)
	if err != nil{
		d2 = 0
	}
	return d1 == d2
}