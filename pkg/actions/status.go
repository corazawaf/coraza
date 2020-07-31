package actions

import(
	"strconv"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Status struct {
	status int
}

func (a *Status) Init(r *engine.Rule, b1 string, errors []string) () {
	a.status, _ = strconv.Atoi(b1)
}

func (a *Status) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Status = a.status
}

func (a *Status) GetType() string{
	return ""
}
