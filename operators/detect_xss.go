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
	engine "github.com/jptosso/coraza-waf"
	"github.com/jptosso/coraza-waf/utils"
)

type DetectXSS struct{}

func (o *DetectXSS) Init(data string) error {
	return nil
}

func (o *DetectXSS) Evaluate(tx *engine.Transaction, value string) bool {
	//TODO this is supposed to capture the vals but libinjection API doesn't return an output
	return utils.IsXSS(value)
}
