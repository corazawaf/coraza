package operators

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Lt struct{
	data string
}

func (o *Lt) Init(data string){
	o.data = data
}

func (o *Lt) Evaluate(tx *engine.Transaction, value string) bool{
	vv := tx.MacroExpansion(o.data)
	data, err := strconv.Atoi(vv)
	if err != nil {
		data = 0
	}
	v, err := strconv.Atoi(value)
	if err != nil {
		v = 0
	}	
	return v < data
}
