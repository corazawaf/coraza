package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Noauditlog struct {
}

func (a *Noauditlog) Init(r *engine.Rule, data string, errors []string) () {

}

func (a *Noauditlog) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	tx.AuditLog = false
}

func (a *Noauditlog) GetType() string{
	return ""
}
