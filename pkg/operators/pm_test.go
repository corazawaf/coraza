package operators

import(
	"testing"
)

func TestPm(t *testing.T) {
    pm := &Pm{}
    pm.Init("abc def ghi")
    if !pm.Evaluate(nil, "test ab abc 123") {
    	t.Errorf("Invalid result for @pm operator")
    }
    if pm.Evaluate(nil, "abedfegih 456") {
        t.Errorf("Invalid result for @pm operator")
    }    
    if !pm.Evaluate(nil, "abcdefghijk456") {
        t.Errorf("Invalid result for @pm operator")
    }    
}