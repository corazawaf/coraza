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
	"strconv"

	engine "github.com/jptosso/coraza-waf"
)

type Eq struct {
	data string
}

func (o *Eq) Init(data string) error {
	o.data = data
	return nil
}

func (o *Eq) Evaluate(tx *engine.Transaction, value string) bool {
	d1, err := strconv.Atoi(tx.MacroExpansion(o.data))
	if err != nil {
		d1 = 0
	}
	d2, err := strconv.Atoi(value)
	if err != nil {
		d2 = 0
	}
	return d1 == d2
}
