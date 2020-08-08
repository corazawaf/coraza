package operators

import(
	"testing"
	_"fmt"
    "github.com/jptosso/coraza-waf/pkg/engine"
)

func TestValidateNid(t *testing.T) {
    vicl := &ValidateNid{}
    vicl.Init("cl .*")

    clok := []string{"11.111.111-1", "111111111"}
    clfail := []string{"11.111.111-2", "111111118"}
    waf := &engine.Waf{}
    waf.Init()
    tx := waf.NewTransaction()
    for _, ok := range clok{
        if !vicl.Evaluate(tx, ok){
            t.Errorf("Invalid NID " + ok)
        }
    }
    for _, fail := range clfail{
        if vicl.Evaluate(tx, fail){
            t.Errorf("Invalid NID")
        }
    }      
}