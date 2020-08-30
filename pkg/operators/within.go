package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strings"
)

type Within struct{
	data string
}

func (o *Within) Init(data string){
	o.data = data
}

func (o *Within) Evaluate(tx *engine.Transaction, value string) bool{
	data := tx.MacroExpansion(o.data)
	return strings.Contains(data, value)
}