package operators

import(
	"testing"
)

func TestRbl(t *testing.T) {
    rbl := &Rbl{}
    rbl.Init("xbl.spamhaus.org")
    // Twitter ip address
    if rbl.Evaluate(nil, "199.16.156.5") {
    	t.Errorf("Invalid result for @rbl operator")
    }
    // Facebook ip address
    if rbl.Evaluate(nil, "176.13.13.13") {
        t.Errorf("Invalid result for @rbl operator")
    }    
    /*
    // We dont have any permanently banned ip address :(
    if !rbl.Evaluate(nil, "71.6.158.166") {
        t.Errorf("Invalid result for @rbl operator, should be blacklisted")
    }    
    */
}