package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type VerifyCC struct{
	
}

func (o *VerifyCC) Init(data string){
	// not implemented
}

func (o *VerifyCC) Evaluate(tx *engine.Transaction, value string) bool{
	//not implemented
    return false
}