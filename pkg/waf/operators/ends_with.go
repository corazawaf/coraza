package operators

import(
	"strings"
	"github.com/jptosso/coraza-waf/pkg/models"
)

type EndsWith struct{
	data string
}

func (o *EndsWith) Init(data string){
	o.data = data
}

func (o *EndsWith) Evaluate(tx *models.Transaction, value string) bool{
	return strings.HasSuffix(value, o.data)
}