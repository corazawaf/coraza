package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"strconv"
)

//NOT IMPLEMENTED
type Skip struct {
	data int
}

func (a *Skip) Init(r *engine.Rule, data string) []string {
	i, err := strconv.Atoi(data)
	if err != nil{
		return []string{"Invalid integer value"}
	}
	a.data = i
	return []string{}
}

func (a *Skip) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Skip = a.data
}

func (a *Skip) GetType() int{
	return engine.ACTION_TYPE_FLOW
}
