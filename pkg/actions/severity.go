package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Severity struct {
}

func (a *Severity) Init(r *engine.Rule, data string) string {
	l := []string{"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG",}
	for _, val := range l {
		if val == data{
			//r.Severity = i
		}
	}
	r.Severity = data
	return ""
}

func (a *Severity) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *Severity) GetType() int{
	return engine.ACTION_TYPE_METADATA
}
