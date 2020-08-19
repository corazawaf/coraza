package operators

import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func TestOpEndsWith(t *testing.T) {
    waf := &engine.Waf{}
    waf.Init()
    tx := waf.NewTransaction()
    op := &EndsWith{}
    op.Init("456")
    result := op.Evaluate(tx, "123456")
    if !result {
    	t.Errorf("Invalid EndsWith operator result")
    }
    result = op.Evaluate(tx, "151235234")
    if result {
        t.Errorf("Invalid EndsWith operator result")
    }    
}