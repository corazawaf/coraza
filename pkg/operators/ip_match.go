package operators
import(
	"net"
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/utils"
	"fmt"
	"strings"
)

type IpMatch struct{
	subnets []*net.IPNet
}

func (o *IpMatch) Init(data string){
	o.subnets = []*net.IPNet{}
	subnets := strings.Split(data, ",")
	for _, sb := range subnets{
		sb = utils.StripSpaces(sb)
		if sb == ""{
			continue
		}
		if !strings.Contains(sb, "/"){
			sb = sb + "/32"
		}		
		_, subnet, err := net.ParseCIDR(sb)
		if err != nil{
			fmt.Println("Invalid CIDR " + sb)
			continue
		}
		o.subnets = append(o.subnets, subnet)
	}
}

func (o *IpMatch) Evaluate(tx *engine.Transaction, value string) bool{
	ip := net.ParseIP(value)
	for _, subnet := range o.subnets{
		if subnet.Contains(ip){
			return true
		}
	}
    return false
}