package actions

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Id struct {
}

func (a *Id) Init(r *engine.Rule, data string) []string {
	i, err := strconv.Atoi(data)
	if err != nil{
		return []string{"Invalid rule ID " + data}
	}
	r.Id = int(i)
	return []string{}
}

func (a *Id) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Id) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
