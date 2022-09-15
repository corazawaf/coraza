// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/rules"
)

type operatorsWrapper = func() rules.RuleOperator

var operators = map[string]operatorsWrapper{}

func init() {
	Register("beginsWith", func() rules.RuleOperator { return &beginsWith{} })
	Register("rx", func() rules.RuleOperator { return &rx{} })
	Register("eq", func() rules.RuleOperator { return &eq{} })
	Register("contains", func() rules.RuleOperator { return &contains{} })
	Register("endsWith", func() rules.RuleOperator { return &endsWith{} })
	Register("inspectFile", func() rules.RuleOperator { return &inspectFile{} })
	Register("ge", func() rules.RuleOperator { return &ge{} })
	Register("gt", func() rules.RuleOperator { return &gt{} })
	Register("le", func() rules.RuleOperator { return &le{} })
	Register("lt", func() rules.RuleOperator { return &lt{} })
	Register("unconditionalMatch", func() rules.RuleOperator { return &unconditionalMatch{} })
	Register("within", func() rules.RuleOperator { return &within{} })
	Register("pmFromFile", func() rules.RuleOperator { return &pmFromFile{} })
	Register("pm", func() rules.RuleOperator { return &pm{} })
	Register("validateByteRange", func() rules.RuleOperator { return &validateByteRange{} })
	Register("validateUrlEncoding", func() rules.RuleOperator { return &validateURLEncoding{} })
	Register("streq", func() rules.RuleOperator { return &streq{} })
	Register("ipMatch", func() rules.RuleOperator { return &ipMatch{} })
	Register("ipMatchFromFile", func() rules.RuleOperator { return &ipMatchFromFile{} })
	Register("ipMatchFromDataset", func() rules.RuleOperator { return &ipMatchFromDataset{} })
	Register("rbl", func() rules.RuleOperator { return &rbl{} })
	Register("validateUtf8Encoding", func() rules.RuleOperator { return &validateUtf8Encoding{} })
	Register("noMatch", func() rules.RuleOperator { return &noMatch{} })
	Register("validateNid", func() rules.RuleOperator { return &validateNid{} })
	Register("geoLookup", func() rules.RuleOperator { return &geoLookup{} })
	Register("detectSQLi", func() rules.RuleOperator { return &detectSQLi{} })
	Register("detectXSS", func() rules.RuleOperator { return &detectXSS{} })
}

// Get returns an operator by name
func Get(name string) (rules.RuleOperator, error) {
	if op, ok := operators[name]; ok {
		return op(), nil
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// Register registers a new operator
// If the operator already exists it will be overwritten
func Register(name string, op func() rules.RuleOperator) {
	operators[name] = op
}
