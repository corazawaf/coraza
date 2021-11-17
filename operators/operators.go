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

	"github.com/jptosso/coraza-waf/v2"
)

type operatorsWrapper = func() coraza.RuleOperator

var operators = map[string]operatorsWrapper{}

func init() {
	RegisterOperator("beginsWith", func() coraza.RuleOperator { return &beginsWith{} })
	RegisterOperator("rx", func() coraza.RuleOperator { return &rx{} })
	RegisterOperator("eq", func() coraza.RuleOperator { return &eq{} })
	RegisterOperator("contains", func() coraza.RuleOperator { return &contains{} })
	RegisterOperator("endsWith", func() coraza.RuleOperator { return &endsWith{} })
	RegisterOperator("inspectFile", func() coraza.RuleOperator { return &inspectFile{} })
	RegisterOperator("ge", func() coraza.RuleOperator { return &ge{} })
	RegisterOperator("gt", func() coraza.RuleOperator { return &gt{} })
	RegisterOperator("le", func() coraza.RuleOperator { return &le{} })
	RegisterOperator("lt", func() coraza.RuleOperator { return &lt{} })
	RegisterOperator("unconditionalMatch", func() coraza.RuleOperator { return &unconditionalMatch{} })
	RegisterOperator("within", func() coraza.RuleOperator { return &within{} })
	RegisterOperator("pmFromFile", func() coraza.RuleOperator { return &pmFromFile{} })
	RegisterOperator("pm", func() coraza.RuleOperator { return &pm{} })
	RegisterOperator("validateByteRange", func() coraza.RuleOperator { return &validateByteRange{} })
	RegisterOperator("validateUrlEncoding", func() coraza.RuleOperator { return &validateURLEncoding{} })
	RegisterOperator("streq", func() coraza.RuleOperator { return &streq{} })
	RegisterOperator("ipMatch", func() coraza.RuleOperator { return &ipMatch{} })
	RegisterOperator("ipMatchFromFile", func() coraza.RuleOperator { return &ipMatchFromFile{} })
	RegisterOperator("rbl", func() coraza.RuleOperator { return &rbl{} })
	RegisterOperator("validateUtf8Encoding", func() coraza.RuleOperator { return &validateUtf8Encoding{} })
	RegisterOperator("noMatch", func() coraza.RuleOperator { return &noMatch{} })
	RegisterOperator("validateNid", func() coraza.RuleOperator { return &validateNid{} })
	RegisterOperator("geoLookup", func() coraza.RuleOperator { return &geoLookup{} })
}
func GetOperator(name string) (coraza.RuleOperator, error) {
	if op, ok := operators[name]; ok {
		return op(), nil
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

func RegisterOperator(name string, op func() coraza.RuleOperator) {
	operators[name] = op
}
