package operators

import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type UnconditionalMatch struct{}

func (o *UnconditionalMatch) Init(data string){
}

func (o *UnconditionalMatch) Evaluate(tx *models.Transaction, value string) bool{
	return true
}