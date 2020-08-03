package actions

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/lua"
	"github.com/jptosso/coraza-waf/pkg/utils"
)

type Exec struct {
	cachedScript string
}

func (a *Exec) Init(r *engine.Rule, data string) error {
	fdata, err := utils.OpenFile(data)
	if err != nil{
		return err
	}
	a.cachedScript = string(fdata)
	return nil
}

func (a *Exec) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
    l := &lua.LuaScript{}
    l.FromString(a.cachedScript)
    err := l.Evaluate(tx, 1000)
    if err != nil{
    	return
    }
}

func (a *Exec) Type() string{
	return ""
}