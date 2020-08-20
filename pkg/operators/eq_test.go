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
    op.Init("123")
    result := op.Evaluate(tx, "123")
    if !result {
    	t.Errorf("Invalid Eq operator result")
    }
    result = op.Evaluate(tx, "aaa")
    if result {
        t.Errorf("Invalid Eq operator result")
    }    

    // aaa should be 0
    op.Init("0")
    result = op.Evaluate(tx, "aaa")
    if !result {
        t.Errorf("Invalid Eq operator result")
    }        
}