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
	RegisterPlugin("beginsWith", func() coraza.RuleOperator { return &beginsWith{} })
	RegisterPlugin("rx", func() coraza.RuleOperator { return &rx{} })
	RegisterPlugin("eq", func() coraza.RuleOperator { return &eq{} })
	RegisterPlugin("contains", func() coraza.RuleOperator { return &contains{} })
	RegisterPlugin("endsWith", func() coraza.RuleOperator { return &endsWith{} })
	RegisterPlugin("inspectFile", func() coraza.RuleOperator { return &inspectFile{} })
	RegisterPlugin("ge", func() coraza.RuleOperator { return &ge{} })
	RegisterPlugin("gt", func() coraza.RuleOperator { return &gt{} })
	RegisterPlugin("le", func() coraza.RuleOperator { return &le{} })
	RegisterPlugin("lt", func() coraza.RuleOperator { return &lt{} })
	RegisterPlugin("unconditionalMatch", func() coraza.RuleOperator { return &unconditionalMatch{} })
	RegisterPlugin("within", func() coraza.RuleOperator { return &within{} })
	RegisterPlugin("pmFromFile", func() coraza.RuleOperator { return &pmFromFile{} })
	RegisterPlugin("pm", func() coraza.RuleOperator { return &pm{} })
	RegisterPlugin("validateByteRange", func() coraza.RuleOperator { return &validateByteRange{} })
	RegisterPlugin("validateUrlEncoding", func() coraza.RuleOperator { return &validateURLEncoding{} })
	RegisterPlugin("streq", func() coraza.RuleOperator { return &streq{} })
	RegisterPlugin("ipMatch", func() coraza.RuleOperator { return &ipMatch{} })
	RegisterPlugin("ipMatchFromFile", func() coraza.RuleOperator { return &ipMatchFromFile{} })
	RegisterPlugin("rbl", func() coraza.RuleOperator { return &rbl{} })
	RegisterPlugin("validateUtf8Encoding", func() coraza.RuleOperator { return &validateUtf8Encoding{} })
	RegisterPlugin("noMatch", func() coraza.RuleOperator { return &noMatch{} })
	RegisterPlugin("validateNid", func() coraza.RuleOperator { return &validateNid{} })
	RegisterPlugin("geoLookup", func() coraza.RuleOperator { return &geoLookup{} })
}

// GetOperator returns an operator by name
func GetOperator(name string) (coraza.RuleOperator, error) {
	if op, ok := operators[name]; ok {
		return op(), nil
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// RegisterPlugin registers a new operator
// If the operator already exists it will be overwritten
func RegisterPlugin(name string, op func() coraza.RuleOperator) {
	operators[name] = op
}
