package lua

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"github.com/yuin/gopher-lua"
	"context"
	"time"
)

type LuaScript struct {
	cachedScript string
}

func (ls *LuaScript) FromFile(path string) () {
	
}

func (ls *LuaScript) FromString(code string) () {
    ls.cachedScript = code
}

func (ls *LuaScript) Evaluate(tx *engine.Transaction, timeout time.Duration) (error) {
    L := lua.NewState()
    defer L.Close()
    bgctx, cancel := context.WithTimeout(context.Background(), timeout*time.Millisecond)
    defer cancel()

    waf := &luaWaf{tx}
    ctx := context.WithValue(bgctx, "waf", waf)
    L.SetContext(ctx)
    L.PreloadModule("waf", luaLoader)
    if err := L.DoString(ls.cachedScript); err != nil {
        return err
    }
    return nil
}

type luaWaf struct{
	Tx *engine.Transaction
}

func luaLoader(L *lua.LState) int {
    // register functions to the table
    mod := L.SetFuncs(L.NewTable(), luaExports)

    // returns the module
    L.Push(mod)
    return 1
}

var luaExports = map[string]lua.LGFunction{
    "version": luaWafVersion,
    "getvar": luaTxGetField,
    "setvar": luaTxSetField,
    "setfirstvar": luaTxSetFieldSingle,

    //Next to implement
    //"getfirstvar": luaTxGetField,
    //"redisset": luaWafVersion,
    //"redisget": luaWafVersion,
    //"rediscmd": luaWafVersion,
    //"error": luaWafVersion,
    //"warn": luaWafVersion,
    //"info": luaWafVersion,
    //"transform": luaWafVersion,
    //"timestamp": luaWafVersion,
    //"servertime": luaWafVersion,
    //"xpath": luaWafVersion,
    //"http": luaWafVersion,
}

func luaWafVersion(L *lua.LState) int {
	L.Push(lua.LString("0.1-alpha"))
    return 1
}

func luaTxGetField(L *lua.LState) int {
	t, ok := L.Context().Value("waf").(*luaWaf)
	if !ok {
	    //fail...
	    return 0
	}
	col := ""
	key := ""
	data := t.Tx.GetField(col, key, []string{})
	table := L.NewTable()
	for _, r := range data{
		table.Append(lua.LString(r.Value))
	}
	L.Push(table)
    return 1
}

func luaTxSetField(L *lua.LState) int {
	waf, ok := L.Context().Value("waf").(*luaWaf)
	if !ok {
	    return 0
	}	
	blacklist := []string{"id"}
	col := L.CheckString(1)
	key := L.CheckString(2)
	newval := L.CheckTable(3)
	data := []string{}
	if utils.ArrayContains(blacklist, col){
		// cannot update this field
		return 0
	}	
	newval.ForEach(func (key lua.LValue, value lua.LValue){
		//TODO is it sorted?
		data = append(data, value.String())
	})
	waf.Tx.Collections[col].Data[key] = data
    return 0
}

func luaTxSetFieldSingle(L *lua.LState) int {
	waf, ok := L.Context().Value("waf").(*luaWaf)
	if !ok {
	    return 0
	}	
	blacklist := []string{"id"}
	col := L.CheckString(1)
	newval := L.CheckString(2)

	if utils.ArrayContains(blacklist, col){
		// cannot update this field
		return 0
	}
	waf.Tx.Collections[col].Data[""] = []string{newval}
    return 0
}