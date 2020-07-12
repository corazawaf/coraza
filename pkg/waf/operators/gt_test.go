package operators

import(
	"testing"
	_"fmt"
)

func TestGt(t *testing.T) {
    gto := &Gt{}
    gto.Init("2500")
    if !gto.Evaluate(nil, "2800") {
    	t.Errorf("Invalid result for @gt operator")
    }
    if gto.Evaluate(nil, "2400") {
        t.Errorf("Invalid result for @gt operator")
    }    
}