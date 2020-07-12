package operators

import(
	"testing"
	_"fmt"
)

func TestGe(t *testing.T) {
    geo := &Ge{}
    geo.Init("2500")
    if !geo.Evaluate(nil, "2800") {
    	t.Errorf("Invalid result for @gt operator")
    }
    if !geo.Evaluate(nil, "2500") {
        t.Errorf("Invalid result for @gt operator")
    }    
    if geo.Evaluate(nil, "2400") {
        t.Errorf("Invalid result for @gt operator")
    }    
}