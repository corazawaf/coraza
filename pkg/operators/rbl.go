package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
	"fmt"
	"net"
	"time"
)

type Rbl struct{
	service string
}

func (o *Rbl) Init(data string){
	o.service = data
	//TODO validate hostname
}

//https://github.com/mrichman/godnsbl
//https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/operators/rbl.cc
func (o *Rbl) Evaluate(tx *engine.Transaction, value string) bool{
	//TODO validate address
	c1 := make(chan bool)
	//captures := []string{}

	addr := fmt.Sprintf("%s.%s", value, o.service)
	go func() {
		res, err := net.LookupHost(addr)
		if err != nil{
			c1 <- false
		}	
		//var status string
		if len(res) > 0 {
			txt, _ := net.LookupTXT(addr)
			if len(txt) > 0 {
				//status = txt[0]
				//captures = append(captures, txt[0])
			}	
		}
		c1 <- true
	}()
	select {
	case res := <-c1:
		if tx.Capture && res{
			tx.ResetCapture()
			//tx.AddCapture()
		}			
		return res
	case <-time.After(1):
		// TIMEOUT
		return false
	}

	return true
}