package actions

import(
	"github.com/jptosso/coraza/pkg/models"
	"github.com/jptosso/coraza/pkg/waf/transformations"
	"fmt"
)

type T struct {}

func (a *T) Init(r *models.Rule, transformation string, errors []string) () {
	transformations := transformations.TransformationsMap()
	tt := transformations[transformation]
	if tt == nil{
		fmt.Println("Unsupported transformation " + transformation)
		return
	}
	tf := models.RuleTransformation{transformation, tt}
	r.Transformations = append(r.Transformations, tf)
}

func (a *T) Evaluate(r *models.Rule, tx *models.Transaction) () {
	
}

func (a *T) GetType() string{
	return ""
}
