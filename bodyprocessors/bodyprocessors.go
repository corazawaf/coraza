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

package bodyprocessors

import (
	"fmt"
	"io"

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

type collectionsMap map[variables.RuleVariable]map[string][]string

type BodyProcessor interface {
	Read(reader io.Reader, mime string, storagePath string) error
	Collections() collectionsMap
	Find(string) (map[string][]string, error)
	VariableHook() variables.RuleVariable
}

type bodyProcessorWrapper = func() BodyProcessor

var processors = map[string]bodyProcessorWrapper{}

func RegisterBodyProcessor(name string, fn func() BodyProcessor) {
	processors[name] = fn
}

func GetBodyProcessor(name string) (BodyProcessor, error) {
	if fn, ok := processors[name]; ok {
		return fn(), nil
	}
	return nil, fmt.Errorf("invalid bodyprocessor %q", name)
}

func init() {
	RegisterBodyProcessor("json", func() BodyProcessor {
		return &jsonBodyProcessor{}
	})
	RegisterBodyProcessor("urlencoded", func() BodyProcessor {
		return &urlencodedBodyProcessor{}
	})
	RegisterBodyProcessor("multipart", func() BodyProcessor {
		return &multipartBodyProcessor{}
	})
	RegisterBodyProcessor("xml", func() BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
