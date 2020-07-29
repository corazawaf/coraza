package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strings"
)

type Within struct{
	Data []string
}

func (o *Within) Init(data string){
	//TODO split with regex
	o.Data = strings.Split(data, " ")
	if len(o.Data) == 1{
		o.Data = strings.Split(data, ",")
	}
	if len(o.Data) == 1{
		o.Data = strings.Split(data, "|")
	}	
}

func (o *Within) Evaluate(tx *engine.Transaction, value string) bool{
	data := o.Data
	if len(o.Data) == 1{
		tdata := o.Data[0]
		tdata = tx.MacroExpansion(tdata)
		data = strings.Split(tdata, " ")
	}
	for _, s:= range data {
		if s == value{
			return true
		}
	}
	return false
}