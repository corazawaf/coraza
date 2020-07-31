package actions


/*
#cgo LDFLAGS: -lluajit-5.1
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
*/
//import "C"
import (
	//"bytes"
	//"unsafe"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

type Exec struct {
	cachedScript []byte
}

func (a *Exec) Init(r *engine.Rule, data string, errors []string) () {
	// Does not require initializer
}

func (a *Exec) Evaluate(r *engine.Rule, tx *engine.Transaction) () {
	/*
	var L = C.luaL_newstate()
	C.luaL_openlibs(L)
	C.lua_getglobal(L, "require")
	C.luaL_loadfile(L, filename) 
	var status = lua_pcall(L, 1, 0, 0)
	*/
}

func (a *Exec) Type() string{
	return ""
}
