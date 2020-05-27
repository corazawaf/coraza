package operators

import(
	"github.com/jptosso/coraza/pkg/models"
)

type Eq struct{
	data string
}

func (o *Eq) Init(data string){
	o.data = data
}

func (o *Eq) Evaluate(tx *models.Transaction, value string) bool{
	return o.data == value
}