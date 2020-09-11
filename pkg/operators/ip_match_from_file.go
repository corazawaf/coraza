// Copyright 2020 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operators

import(
	"github.com/jptosso/coraza-waf/pkg/engine"
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

func (o *IpMatchFromFile) Evaluate(tx *engine.Transaction, value string) bool{
	ip := net.ParseIP(value)
	for _, n := range o.ranges{
		if n.Contains(ip){
			return true
		}
	}
	return false
}