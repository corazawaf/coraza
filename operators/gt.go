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

	"github.com/jptosso/coraza-waf/v2"
)

type gt struct {
	data coraza.Macro
}

func (o *gt) Init(data string) error {
	macro, err := coraza.NewMacro(data)
	if err != nil {
		return err
	}
	o.data = *macro
	return nil
}

func (o *gt) Evaluate(tx *coraza.Transaction, value string) bool {
	v, err := strconv.Atoi(value)
	if err != nil {
		v = 0
	}
	data := o.data.Expand(tx)
	k, err := strconv.Atoi(data)
	if err != nil {
		k = 0
	}
	return k < v
}
