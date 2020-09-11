package actions
import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func TestInitcol(t *testing.T){
	w := engine.NewWaf()
	tx := w.NewTransaction()
	r := &engine.Rule{}
	r.Init()

	ic := InitCol{}
	if ic.Init(r, "session=test") != ""{
		t.Error("Failed to initialize persistent collection")
	}
	ic.Evaluate(r, tx)
	if len(tx.PersistentCollections) == 0{
		t.Error("Failed to initialize persistent collection")
	}
}