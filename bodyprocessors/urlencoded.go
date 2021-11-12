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
	"io"
	"strconv"
	"strings"

	"github.com/jptosso/coraza-waf/v2/types/variables"
	"github.com/jptosso/coraza-waf/v2/utils"
)

type urlencodedBodyProcessor struct {
	collections *collectionsMap
}

func (ue *urlencodedBodyProcessor) Read(reader io.Reader, _ string, _ string) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	b := buf.String()
	//TODO add url encode validation
	//tx.GetCollection(VARIABLE_URLENCODED_ERROR).Set("", []string{err.Error()})
	values := utils.ParseQuery(b, "&")
	m := map[string][]string{}
	for k, vs := range values {
		m[k] = vs
	}
	ue.collections = &collectionsMap{
		variables.ArgsPost: m,
		variables.Args:     m,
		variables.RequestBody: map[string][]string{
			"": {b},
		},
		variables.RequestBodyLength: map[string][]string{
			"": {strconv.Itoa(len(b))},
		},
	}
	return nil
}

func (js *urlencodedBodyProcessor) Collections() collectionsMap {
	return *js.collections
}

func (js *urlencodedBodyProcessor) Find(expr string) (map[string][]string, error) {
	return nil, nil
}

func (js *urlencodedBodyProcessor) VariableHook() variables.RuleVariable {
	return variables.Json
}

var (
	_ BodyProcessor = &urlencodedBodyProcessor{}
)
