package operators

import(
	"testing"
)

func TestLt(t *testing.T) {
    lt := &Lt{}
    lt.Init("2500")
    if !lt.Evaluate(nil, "2400") {
    	t.Errorf("Invalid result for @lt operator")
    }
    if lt.Evaluate(nil, "2500") {
        t.Errorf("Invalid result for @lt operator")
    }    
    if lt.Evaluate(nil, "2800") {
        t.Errorf("Invalid result for @lt operator")
    }    
}