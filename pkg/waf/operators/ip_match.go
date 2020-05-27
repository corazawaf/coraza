package operators
import(
	"net"
	"github.com/jptosso/coraza-waf/pkg/models"
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
		_, subnet, err := net.ParseCIDR(sb)
		if err != nil{
			//we add /32 in case of a single ip address
			_, subnet, err = net.ParseCIDR(sb+ "/32")
			if err != nil{
				fmt.Println("Error parsing network " + sb)
				continue
			}
		}
		o.subnets = append(o.subnets, subnet)
	}
}

func (o *IpMatch) Evaluate(tx *models.Transaction, value string) bool{
	ip := net.ParseIP(value)
	for _, subnet := range o.subnets{
		if subnet.Contains(ip){
			return true
		}
	}
    return false
}