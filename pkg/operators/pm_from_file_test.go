package operators

import(
	"testing"
	_"fmt"
)

func TestPmFromFile1(t *testing.T) {
    match := []string{
        "this is a test1 string with many tests.",
        "asdfjava.io.BufferedInputStream=test asdfasdf",
    }
    nomatch := []string{
        "this is the same test string without a match.",
    }
    pmf := &PmFromFile{}
    pmf.Init("")
    pmf.Data = []string{"test1", "match1", "java.io.BufferedInputStream=test"}
    for _, m := range match {
        if !pmf.Evaluate(nil, m) {
            t.Errorf("Invalid result for pmf, must match")
        }
    }
    for _, nm := range nomatch {
        if pmf.Evaluate(nil, nm) {
            t.Errorf("Invalid result for musn't match")
        }    
    }
}