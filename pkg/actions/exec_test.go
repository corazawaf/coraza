package actions

import(
	"testing"
	"os"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func TestExec(t *testing.T){
	exec := &Exec{}
	waf := &engine.Waf{}
	waf.Init()
	r := &engine.Rule{}
	r.Init()
	tx := waf.NewTransaction()
	path, _ := os.Getwd()
	path += "/../../test/data/exec.lua"
	errors := exec.Init(r, path)
	if len(errors) > 0{
		t.Error("Failed to load lua file")
	}
	exec.Evaluate(r, tx)
	
	id := tx.GetSingleCollection("id")
	if id == "test"{
		t.Error("Failed to update transaction through exec LUA, shouldn't update ID")
	}

	body := tx.GetSingleCollection("response_body")
	if body != "test"{
		t.Error("Failed to update transaction through exec LUA, got", body)
	}	
}