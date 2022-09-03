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
	"github.com/corazawaf/libinjection-go"

	"github.com/corazawaf/coraza/v2"
)

type detectXSS struct {
}

func (o *detectXSS) Init(data string) error {
	return nil
}

func (o *detectXSS) Evaluate(tx *coraza.Transaction, value string) bool {
	return libinjection.IsXSS(value)
}
