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
	engine "github.com/jptosso/coraza-waf/v1"
	"github.com/jptosso/coraza-waf/v1/utils"
)

type DetectSQLi struct{}

func (o *DetectSQLi) Init(data string) error {
	return nil
}

func (o *DetectSQLi) Evaluate(tx *engine.Transaction, value string) bool {
	res, capture := utils.IsSQLi(value)
	tx.CaptureField(1, capture)
	return res
}
