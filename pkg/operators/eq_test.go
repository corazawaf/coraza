package operators

import(
	"testing"
	"github.com/jptosso/coraza-waf/pkg/engine"
)

func TestOpEq(t *testing.T) {
    waf := &engine.Waf{}
    waf.Init()
    tx := waf.NewTransaction()
    op := &Eq{}
    op.Init("test123")
    result := op.Evaluate(tx, "test123")
    if !result {
    	t.Errorf("Invalid Eq operator result")
    }
    result = op.Evaluate(tx, "test455")
    if result {
        t.Errorf("Invalid Eq operator result")
    }    
}