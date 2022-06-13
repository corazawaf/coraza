// Copyright 2022 Juan Pablo Tosso
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
	"context"
	"fmt"
	"net"
	"time"

	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/coraza/v2/types/variables"
)

const timeout = 500 * time.Millisecond

type rbl struct {
	service  string
	resolver *net.Resolver
}

func (o *rbl) Init(data string) error {
	o.service = data
	o.resolver = net.DefaultResolver
	// TODO validate hostname
	return nil
}

// https://github.com/mrichman/godnsbl
// https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/operators/rbl.cc
func (o *rbl) Evaluate(tx *coraza.Transaction, ipAddr string) bool {
	// TODO validate address
	resC := make(chan bool)
	ctx, cancel := context.WithCancel(context.Background())

	defer func() {
		cancel()
		close(resC)
	}()

	addr := fmt.Sprintf("%s.%s", ipAddr, o.service)
	captures := []string{}
	go func(ctx context.Context) {
		res, err := o.resolver.LookupHost(ctx, addr)

		if err != nil {
			resC <- false
			return
		}
		// var status string
		if len(res) > 0 {
			txt, err := o.resolver.LookupTXT(ctx, addr)
			if err != nil {
				resC <- false
				return
			}

			if len(txt) > 0 {
				status := txt[0]
				captures = append(captures, status)
				tx.GetCollection(variables.TX).Set("httpbl_msg", []string{status})
			}
		}

		resC <- true
	}(ctx)

	select {
	case res := <-resC:
		if res && len(captures) > 0 {
			tx.CaptureField(0, captures[0])
		}
		return res
	case <-time.After(timeout):
		return false
	}
}
