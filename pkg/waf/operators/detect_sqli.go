package operators

import(
	"github.com/jptosso/coraza/pkg/utils"
	"github.com/jptosso/coraza/pkg/models"
)

type DetectSQLi struct{}

func (o *DetectSQLi) Init(data string){
}

func (o *DetectSQLi) Evaluate(tx *models.Transaction, value string) bool{
	res, _ := utils.IsSQLi(value)
	return res
}