package operators

import(
	"strconv"
	"github.com/jptosso/coraza/pkg/models"
)

type Ge struct{
	data int
}

func (o *Ge) Init(data string){
	k, _ := strconv.Atoi(data)
	o.data = k
}

func (o *Ge) Evaluate(tx *models.Transaction, value string) bool{
	v, err := strconv.Atoi(value)
	if  err != nil{
		return false
	}
	return v >= o.data
}