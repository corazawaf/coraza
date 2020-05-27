package operators
import(
	"github.com/jptosso/coraza-waf/pkg/models"
)

type Streq struct{
	data string
}

func (o *Streq) Init(data string){
	o.data = data
}

func (o *Streq) Evaluate(tx *models.Transaction, value string) bool{
	return o.data == value
}