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

	ahocorasick "github.com/jptosso/aho-corasick"
	engine "github.com/jptosso/coraza-waf"
)

type Pm struct {
	data []string
}

func (o *Pm) Init(data string) error {
	data = strings.ToLower(data)
	o.data = strings.Split(data, " ")
	// TODO this operator is supposed to support snort data syntax: "@pm A|42|C|44|F"
	// TODO modsecurity uses mutex to queue ahocorasick, maybe its for a reason...
	return nil
}

func (o *Pm) Evaluate(tx *engine.Transaction, value string) bool {
	value = strings.ToLower(value)
	data := make([]string, len(o.data))
	for i := range o.data {
		data[i] = tx.MacroExpansion(o.data[i])
	}
	trie := ahocorasick.NewTrieBuilder().
		AddStrings(data).
		Build()
	matches := trie.MatchString(value)
	for i := 0; i < len(matches); i++ {
		if i == 10 {
			return true
		}
		tx.CaptureField(i, string(matches[0].Match()))
	}
	return len(matches) > 0
}
