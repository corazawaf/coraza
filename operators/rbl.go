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
	"fmt"
	"net"
	"time"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

type rbl struct {
	service string
}

func (o *rbl) Init(data string) error {
	o.service = data
	// TODO validate hostname
	return nil
}

// https://github.com/mrichman/godnsbl
// https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/operators/rbl.cc
func (o *rbl) Evaluate(tx *coraza.Transaction, value string) bool {
	// TODO validate address
	c1 := make(chan bool)
	captures := []string{}

	addr := fmt.Sprintf("%s.%s", value, o.service)
	go func() {
		res, err := net.LookupHost(addr)
		if err != nil {
			c1 <- false
		}
		// var status string
		if len(res) > 0 {
			txt, _ := net.LookupTXT(addr)
			if len(txt) > 0 {
				status := txt[0]
				captures = append(captures, txt[0])
				tx.GetCollection(variables.TX).Set("httpbl_msg", []string{status})
			}
		}
		c1 <- true
	}()
	select {
	case res := <-c1:
		if res && len(captures) > 0 {
			tx.CaptureField(0, captures[0])
		}
		return res
	case <-time.After(1):
		// TIMEOUT
		return false
	}
}
