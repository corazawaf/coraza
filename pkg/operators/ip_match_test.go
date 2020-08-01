package operators

import(
	"testing"
	_"fmt"
)

func TestOneAddress(t *testing.T) {
    addrok := "127.0.0.1"
    addrfail := "127.0.0.2"
    cidr := "127.0.0.1/32"
    ipm := &IpMatch{}
    ipm.Init(cidr)
    if !ipm.Evaluate(nil, addrok) {
    	t.Errorf("Invalid result for single CIDR IpMatch")
    }
    if ipm.Evaluate(nil, addrfail) {
        t.Errorf("Invalid result for single CIDR IpMatch")
    }    
}

func TestMultipleAddress(t *testing.T) {
    addrok := []string{"127.0.0.1", "192.168.0.1", "192.168.0.253"}
    addrfail := []string{"127.0.0.2", "192.168.1.1"}
    cidr := "127.0.0.1, 192.168.0.0/24"
    ipm := &IpMatch{}
    ipm.Init(cidr)
    for _, ok := range addrok{
        if !ipm.Evaluate(nil, ok) {
            t.Errorf("Invalid result for single CIDR IpMatch " + ok)
        }
    }

    for _, fail := range addrfail{
        if ipm.Evaluate(nil, fail) {
            t.Errorf("Invalid result for single CIDR IpMatch" + fail)
        }
    }  
}