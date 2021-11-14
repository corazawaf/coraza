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

	engine "github.com/jptosso/coraza-waf/v2"
)

type operatorsWrapper = func() engine.RuleOperator

var operators = map[string]operatorsWrapper{}

func init() {
	RegisterOperator("beginsWith", func() engine.RuleOperator { return &beginsWith{} })
	RegisterOperator("rx", func() engine.RuleOperator { return &rx{} })
	RegisterOperator("eq", func() engine.RuleOperator { return &eq{} })
	RegisterOperator("contains", func() engine.RuleOperator { return &contains{} })
	RegisterOperator("endsWith", func() engine.RuleOperator { return &endsWith{} })
	RegisterOperator("inspectFile", func() engine.RuleOperator { return &inspectFile{} })
	RegisterOperator("ge", func() engine.RuleOperator { return &ge{} })
	RegisterOperator("gt", func() engine.RuleOperator { return &gt{} })
	RegisterOperator("le", func() engine.RuleOperator { return &le{} })
	RegisterOperator("lt", func() engine.RuleOperator { return &lt{} })
	RegisterOperator("unconditionalMatch", func() engine.RuleOperator { return &unconditionalMatch{} })
	RegisterOperator("within", func() engine.RuleOperator { return &within{} })
	RegisterOperator("pmFromFile", func() engine.RuleOperator { return &pmFromFile{} })
	RegisterOperator("pm", func() engine.RuleOperator { return &pm{} })
	RegisterOperator("validateByteRange", func() engine.RuleOperator { return &validateByteRange{} })
	RegisterOperator("validateUrlEncoding", func() engine.RuleOperator { return &validateUrlEncoding{} })
	RegisterOperator("streq", func() engine.RuleOperator { return &streq{} })
	RegisterOperator("ipMatch", func() engine.RuleOperator { return &ipMatch{} })
	RegisterOperator("ipMatchFromFile", func() engine.RuleOperator { return &ipMatchFromFile{} })
	RegisterOperator("rbl", func() engine.RuleOperator { return &rbl{} })
	RegisterOperator("validateUtf8Encoding", func() engine.RuleOperator { return &validateUtf8Encoding{} })
	RegisterOperator("noMatch", func() engine.RuleOperator { return &noMatch{} })
	RegisterOperator("validateNid", func() engine.RuleOperator { return &validateNid{} })
}
func GetOperator(name string) (engine.RuleOperator, error) {
	if op, ok := operators[name]; ok {
		return op(), nil
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

func RegisterOperator(name string, op func() engine.RuleOperator) {
	operators[name] = op
}
