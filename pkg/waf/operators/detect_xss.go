package operators

import(
	"github.com/jptosso/coraza/pkg/utils"
	"github.com/jptosso/coraza/pkg/models"
)

type DetectXSS struct{}

func (o *DetectXSS) Init(data string){
}

func (o *DetectXSS) Evaluate(tx *models.Transaction, value string) bool{
	return utils.IsXSS(value)
}