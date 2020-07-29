package operators

import(
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type DetectSQLi struct{}

func (o *DetectSQLi) Init(data string){
}

func (o *DetectSQLi) Evaluate(tx *engine.Transaction, value string) bool{
	res, _ := utils.IsSQLi(value)
	return res
}