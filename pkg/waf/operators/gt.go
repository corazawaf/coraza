package operators

import(
	"github.com/jptosso/coraza-waf/pkg/models"
	"strconv"
)

type Gt struct{
	data int
}

func (o *Gt) Init(data string){
	k, _ := strconv.Atoi(data)
	o.data = k
}

func (o *Gt) Evaluate(tx *models.Transaction, value string) bool{
	v, err := strconv.Atoi(value)
	if  err != nil{
		return false
	}
	return o.data < v
}