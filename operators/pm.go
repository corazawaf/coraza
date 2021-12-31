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

	"github.com/cloudflare/ahocorasick"
	"github.com/jptosso/coraza-waf/v2"
)

// TODO according to coraza researchs, re2 matching is faster than ahocorasick
// maybe we should switch in the future
// pm is always lowercase
type pm struct {
	matcher *ahocorasick.Matcher
	// dict is used for capturing
	dict []string
}

func (o *pm) Init(data string) error {
	data = strings.ToLower(data)
	o.dict = strings.Split(data, " ")
	o.matcher = ahocorasick.NewStringMatcher(o.dict)
	// TODO this operator is supposed to support snort data syntax: "@pm A|42|C|44|F"
	// TODO modsecurity uses mutex to queue ahocorasick, maybe its for a reason...
	return nil
}

func (o *pm) Evaluate(tx *coraza.Transaction, value string) bool {
	value = strings.ToLower(value)
	matches := o.matcher.MatchThreadSafe([]byte(value))
	for i := 0; i < len(matches); i++ {
		if i == 10 {
			return true
		}
		tx.CaptureField(i, o.dict[matches[i]])
	}
	return len(matches) > 0
}

var _ coraza.RuleOperator = (*pm)(nil)
