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
	"strings"

	"github.com/corazawaf/coraza/v3"
	engine "github.com/corazawaf/coraza/v3"
)

type ipMatchFromFile struct {
	ip *ipMatch
}

func (o *ipMatchFromFile) Init(options coraza.RuleOperatorOptions) error {
	data := options.Arguments

	o.ip = &ipMatch{}
	subnets := strings.ReplaceAll(data, "\n", ",")
	opts := coraza.RuleOperatorOptions{
		Arguments: subnets,
	}
	return o.ip.Init(opts)
}

func (o *ipMatchFromFile) Evaluate(tx *engine.Transaction, value string) bool {
	return o.ip.Evaluate(tx, value)
}
