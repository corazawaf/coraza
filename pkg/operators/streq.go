package operators
import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Streq struct{
	data string
}

func (o *Streq) Init(data string){
	o.data = data
}

func (o *Streq) Evaluate(tx *engine.Transaction, value string) bool{
	return o.data == value
}