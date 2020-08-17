package engine

import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/engine/persistence"
)

var engine PersistenceEngine
var col *PersistentCollection

func TestInitialization(t *testing.T){
	engine = &persistence.MemoryEngine{}
	engine.Init("")
	col = &PersistentCollection{}
	col.Init(engine, "testapp", "SESSION", "127.0.0.1")

	test := col.GetData()
	test["TEST"] = []string{"123"}
	col.SetData(test)
	col.Save()

	// we reset the persistent collection
	col = &PersistentCollection{}
	col.Init(engine, "testapp", "SESSION", "127.0.0.1")

	data := col.GetData()
	if len(data) == 0{
		t.Error("Failed to retrieve persistent collection")
	}

	if len(data["TEST"]) != 1{
		t.Error("Failed to retrieve persistent collection")
	}	

	if data["TEST"][0] != "123"{
		t.Error("Failed to retrieve persistent collection")
	}		

	if data["IS_NEW"][0] != "1"{
		t.Error("Failed to retrieve persistent collection")
	}			
}