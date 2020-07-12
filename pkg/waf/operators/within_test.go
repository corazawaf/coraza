package operators

import(
	"testing"
	_"fmt"
)

func TestWithin(t *testing.T) {
    w := &Within{}
    w.Init("test,secondtest,thirdtest,fourthtest")
    okr := []string{"test", "secondtest"}
    failr := []string{"testo", "testuru"}

    for _, ok := range okr{
        if !w.Evaluate(nil, ok) {
            t.Errorf("Invalid result for @within operator")
        } 
    }

    for _, fail := range failr{
        if w.Evaluate(nil, fail) {
            t.Errorf("Invalid result for @within operator")
        } 
    }    
}