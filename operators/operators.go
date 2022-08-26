// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"

	"github.com/corazawaf/coraza/v3"
)

type operatorsWrapper = func() coraza.RuleOperator

var operators = map[string]operatorsWrapper{}

func init() {
	Register("beginsWith", func() coraza.RuleOperator { return &beginsWith{} })
	Register("rx", func() coraza.RuleOperator { return &rx{} })
	Register("eq", func() coraza.RuleOperator { return &eq{} })
	Register("contains", func() coraza.RuleOperator { return &contains{} })
	Register("endsWith", func() coraza.RuleOperator { return &endsWith{} })
	Register("inspectFile", func() coraza.RuleOperator { return &inspectFile{} })
	Register("ge", func() coraza.RuleOperator { return &ge{} })
	Register("gt", func() coraza.RuleOperator { return &gt{} })
	Register("le", func() coraza.RuleOperator { return &le{} })
	Register("lt", func() coraza.RuleOperator { return &lt{} })
	Register("unconditionalMatch", func() coraza.RuleOperator { return &unconditionalMatch{} })
	Register("within", func() coraza.RuleOperator { return &within{} })
	Register("pmFromFile", func() coraza.RuleOperator { return &pmFromFile{} })
	Register("pm", func() coraza.RuleOperator { return &pm{} })
	Register("validateByteRange", func() coraza.RuleOperator { return &validateByteRange{} })
	Register("validateUrlEncoding", func() coraza.RuleOperator { return &validateURLEncoding{} })
	Register("streq", func() coraza.RuleOperator { return &streq{} })
	Register("ipMatch", func() coraza.RuleOperator { return &ipMatch{} })
	Register("ipMatchFromFile", func() coraza.RuleOperator { return &ipMatchFromFile{} })
	Register("ipMatchFromDataset", func() coraza.RuleOperator { return &ipMatchFromDataset{} })
	Register("rbl", func() coraza.RuleOperator { return &rbl{} })
	Register("validateUtf8Encoding", func() coraza.RuleOperator { return &validateUtf8Encoding{} })
	Register("noMatch", func() coraza.RuleOperator { return &noMatch{} })
	Register("validateNid", func() coraza.RuleOperator { return &validateNid{} })
	Register("geoLookup", func() coraza.RuleOperator { return &geoLookup{} })
	Register("detectSQLi", func() coraza.RuleOperator { return &detectSQLi{} })
	Register("detectXSS", func() coraza.RuleOperator { return &detectXSS{} })
}

// Get returns an operator by name
func Get(name string) (coraza.RuleOperator, error) {
	if op, ok := operators[name]; ok {
		return op(), nil
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// Register registers a new operator
// If the operator already exists it will be overwritten
func Register(name string, op func() coraza.RuleOperator) {
	operators[name] = op
}
