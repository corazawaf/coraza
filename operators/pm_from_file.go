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
	"fmt"
	"strings"
	"sync"

	ahocorasick "github.com/jptosso/aho-corasick"
	engine "github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/utils"
)

type PmFromFile struct {
	Data []string
	trie *ahocorasick.Trie
	mux  *sync.RWMutex
}

func (o *PmFromFile) Init(data string) error {
	o.Data = []string{}
	o.mux = &sync.RWMutex{}
	b, err := utils.OpenFile(data, true, "")
	content := string(b)
	if err != nil {
		return fmt.Errorf("error reading path %s", data)
	}
	sp := strings.Split(string(content), "\n")
	for _, l := range sp {
		if len(l) == 0 {
			continue
		}
		l = strings.ReplaceAll(l, "\r", "") //CLF
		if l[0] != '#' {
			o.Data = append(o.Data, strings.ToLower(l))
		}
	}
	o.trie = ahocorasick.NewTrieBuilder().
		AddStrings(o.Data).
		Build()
	return nil
}

func (o *PmFromFile) Evaluate(tx *engine.Transaction, value string) bool {
	o.mux.RLock()
	defer o.mux.RUnlock()
	value = strings.ToLower(value)
	matches := o.trie.MatchString(value)
	for i := 0; i < len(matches); i++ {
		if i == 10 {
			return true
		}
		tx.CaptureField(i, string(matches[0].Match()))
	}
	return len(matches) > 0
}
