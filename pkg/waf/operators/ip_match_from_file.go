package operators

import(
	"github.com/jptosso/coraza-waf/pkg/models"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"net"
	"strings"
	"fmt"
)


type IpMatchFromFile struct{
	ranges []*net.IPNet
}

func (o *IpMatchFromFile) Init(data string){
	list, err := utils.OpenFile(data)
	if err != nil{
		fmt.Println("Error opening " + data)
		return
	}
	spl := strings.Split(string(list), "\n")
	for _, n := range spl{
		n = utils.StripSpaces(n)
		if n == ""{
			continue
		}		
		if !strings.Contains(n, "/"){
			n = n + "/32"
		}
		_, subnet, err := net.ParseCIDR(n)
		if err != nil{
			fmt.Println("Invalid CIDR " + n)
			continue
		}
		o.ranges = append(o.ranges, subnet)
	}
}

func (o *IpMatchFromFile) Evaluate(tx *models.Transaction, value string) bool{
	ip := net.ParseIP(value)
	for _, n := range o.ranges{
		if n.Contains(ip){
			return true
		}
	}
	return false
}