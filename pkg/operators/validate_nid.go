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

import (
	"github.com/jptosso/coraza-waf/pkg/engine"
	"github.com/jptosso/coraza-waf/pkg/operators/nids"
	log "github.com/sirupsen/logrus"
	"regexp"
	"strings"
)

type ValidateNid struct {
	fn  nids.Nid
	rgx string
}

func (o *ValidateNid) Init(data string) {
	spl := strings.SplitN(data, " ", 2)
	if len(spl) != 2{
		log.Error("Invalid @validateNid argument")
		return 
	}
	o.fn = nids.NidMap()[spl[0]]
	o.rgx = spl[1]
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
		if o.fn.Evaluate(m[0]) {
			res = true
			if tx.Capture {
				tx.CaptureField(i, m[0])
			}
		}
	}
	return res
}
