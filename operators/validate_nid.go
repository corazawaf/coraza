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
	"regexp"
	"strings"

	engine "github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/operators/nids"
)

type ValidateNid struct {
	fn  nids.Nid
	rgx string
}

func (o *ValidateNid) Init(data string) error {
	spl := strings.SplitN(data, " ", 2)
	if len(spl) != 2 {
		return fmt.Errorf("Invalid @validateNid argument")
	}
	o.fn = nids.NidMap()[spl[0]]
	o.rgx = spl[1]
	return nil
}

func (o *ValidateNid) Evaluate(tx *engine.Transaction, value string) bool {
	re, _ := regexp.Compile(o.rgx)
	matches := re.FindAllStringSubmatch(value, -1)
	if tx.Capture {
		tx.ResetCapture()
	}

	res := false
	for i, m := range matches {
		if i >= 10 {
			break
		}
		//should we capture more than one NID?
		if o.fn(m[0]) {
			res = true
			if tx.Capture {
				tx.CaptureField(i, m[0])
			}
		}
	}
	return res
}
