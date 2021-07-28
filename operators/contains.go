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
	"strings"

	engine "github.com/jptosso/coraza-waf"
)

type Contains struct {
	data string
}

func (o *Contains) Init(data string) error {
	o.data = data
	return nil
}

func (o *Contains) Evaluate(tx *engine.Transaction, value string) bool {
	data := tx.MacroExpansion(o.data)
	return strings.Contains(value, data)
}
