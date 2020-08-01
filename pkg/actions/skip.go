package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strconv"
)

//NOT IMPLEMENTED
type Skip struct {
	data int
}

func (a *Skip) Init(r *engine.Rule, data string, errors []string) () {
	i, err := strconv.Atoi(data)
	if err != nil{

	}
	a.data = i
}

func (a *Skip) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Skip = a.data
}

func (a *Skip) GetType() string{
	return ""
}
