package plugins

import (
	"sync"

	"github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/transformations"
)

//TODO for v2, the plugin manager should be able to write
// elements directly to each map of operators, etc...

type PluginOperatorWrapper = func() coraza.Operator
type PluginActionWrapper = func() coraza.RuleAction

var CustomOperators = sync.Map{}
var CustomActions = sync.Map{}
var CustomTransformations = sync.Map{}

func RegisterOperator(name string, operator PluginOperatorWrapper) {
	CustomOperators.Store(name, operator)
}

func RegisterAction(name string, action PluginActionWrapper) {
	CustomActions.Store(name, action)
}

func RegisterTransformation(name string, transformation transformations.Transformation) {
	CustomTransformations.Store(name, transformation)
}
