package operators

import(
	"github.com/jptosso/coraza/pkg/models"
)

type FuzzyHash struct{
	data string
}

func (o *FuzzyHash) Init(data string){
	o.data = data
}

func (o *FuzzyHash) Evaluate(tx *models.Transaction, value string) bool{
	return false
}