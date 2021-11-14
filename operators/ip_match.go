// Copyright 2021 Juan Pablo Tosso
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

import (
	"net"
	"strings"

	engine "github.com/jptosso/coraza-waf/v2"
)

type ipMatch struct {
	subnets []*net.IPNet
}

func (o *ipMatch) Init(data string) error {
	o.subnets = []*net.IPNet{}
	subnets := strings.Split(data, ",")
	for _, sb := range subnets {
		sb = strings.TrimSpace(sb)
		if sb == "" {
			continue
		}
		if strings.Contains(sb, ":") && !strings.Contains(sb, "/") {
			//ipv6
			sb = sb + "/128"
		} else if strings.Contains(sb, ".") && !strings.Contains(sb, "/") {
			//ipv4
			sb = sb + "/32"
		}
		_, subnet, err := net.ParseCIDR(sb)
		if err != nil {
			continue
		}
		o.subnets = append(o.subnets, subnet)
	}
	return nil
}

func (o *ipMatch) Evaluate(tx *engine.Transaction, value string) bool {
	ip := net.ParseIP(value)
	for _, subnet := range o.subnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}
