package actions

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/transformations"
	"fmt"
)

type T struct {}

func (a *T) Init(r *engine.Rule, transformation string, errors []string) () {
	if transformation == "none" {
		//remove elements
		r.Transformations = r.Transformations[:0]
		return
	}
	transformations := transformations.TransformationsMap()
	tt := transformations[transformation]
	if tt == nil{
		fmt.Println("Unsupported transformation " + transformation)
		return
	}
	tf := engine.RuleTransformation{transformation, tt}
	r.Transformations = append(r.Transformations, tf)
}

func (a *T) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	
}

func (a *T) GetType() string{
	return ""
}
