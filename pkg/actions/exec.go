package actions

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/lua"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type Exec struct {
	cachedScript string
}

func (a *Exec) Init(r *engine.Rule, data string) string {
	fdata, err := utils.OpenFile(data)
	if err != nil{
		return "Cannot load file " + data
	}
	a.cachedScript = string(fdata)
	return ""
}

func (a *Exec) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
    l := &lua.LuaScript{}
    l.FromString(a.cachedScript)
    l.Evaluate(tx, 1000)
}

func (a *Exec) GetType() int{
	return engine.ACTION_TYPE_NONDISRUPTIVE
}