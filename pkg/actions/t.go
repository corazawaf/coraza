package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/transformations"
)

type T struct {}

func (a *T) Init(r *engine.Rule, transformation string) []string {
	if transformation == "none" {
		//remove elements
		r.Transformations = r.Transformations[:0]
		return []string{}
	}
	transformations := transformations.TransformationsMap()
	tt := transformations[transformation]
	if tt == nil{
		return []string{"Unsupported transformation " + transformation}
	}
	tf := engine.RuleTransformation{transformation, tt}
	r.Transformations = append(r.Transformations, tf)
	return []string{}
}

func (a *T) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	// Not evaluated
}

func (a *T) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
}
