package operators

import(
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type DetectXSS struct{}

func (o *DetectXSS) Init(data string){
}

func (o *DetectXSS) Evaluate(tx *engine.Transaction, value string) bool{
	return utils.IsXSS(value)
}