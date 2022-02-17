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
	"github.com/corazawaf/coraza/v2"
	"github.com/corazawaf/libinjection-go"
)

type detectSQLi struct {
}

func (o *detectSQLi) Init(data string) error {
	return nil
}

func (o *detectSQLi) Evaluate(tx *coraza.Transaction, value string) bool {
	res, fingerprint := libinjection.IsSQLi(value)
	if !res {
		return false
	}
	if tx.Capture {
		tx.CaptureField(0, string(fingerprint))
	}
	return true
}
