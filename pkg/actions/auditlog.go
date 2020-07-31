package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Auditlog struct {

}
func (a *Auditlog) Init(r *engine.Rule, b1 string, errors []string) () {
	// Does not require initializer
}

func (a *Auditlog) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.Log = true
}

func (a *Auditlog) GetType() string{
	return "nd"
}