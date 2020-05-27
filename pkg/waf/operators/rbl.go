package operators

import(
	"github.com/jptosso/coraza-waf/pkg/models"
	"fmt"
	"net"
)

type Rbl struct{
	service string
}

func (o *Rbl) Init(data string){
	o.service = data
}

//https://github.com/mrichman/godnsbl
//https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/operators/rbl.cc
func (o *Rbl) Evaluate(tx *models.Transaction, value string) bool{
	//TODO validar la ip
	host := value
	addr := fmt.Sprintf("%s.%s", host, o.service)
	res, err := net.LookupHost(addr)
	if len(res) > 0 {
		txt, _ := net.LookupTXT(addr)
		if len(txt) > 0 {
			//text = txt[0]
		}
		//TODO agregar al capture
		return true
	}
	if err != nil{
		//ERROR
		return false
	}
	if tx.Capture {
		
	}
	return false
}