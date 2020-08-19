package operators

import(
	"testing"
)

func TestLe(t *testing.T) {
    le := &Le{}
    le.Init("2500")
    if !le.Evaluate(nil, "2400") {
    	t.Errorf("Invalid result for @le operator")
    }
    if !le.Evaluate(nil, "2500") {
        t.Errorf("Invalid result for @le operator")
    }    
    if le.Evaluate(nil, "2800") {
        t.Errorf("Invalid result for @le operator")
    }    
}