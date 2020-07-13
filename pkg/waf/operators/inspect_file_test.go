package operators

import(
	"testing"
	_"fmt"
)

func TestInspectFile(t *testing.T) {
    ipf := &InspectFile{}
    ipf.Init("/bin/echo")
    if !ipf.Evaluate(nil, "test") {
    	t.Errorf("/bin/echo returned exit code other than 0")
    }
    ipf.Init("/bin/nonexistant")
    if ipf.Evaluate(nil, "test") {
        t.Errorf("/bin/nonexistant returned an invalid exit code")
    }    
}