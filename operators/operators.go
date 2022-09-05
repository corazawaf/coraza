// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type operatorsWrapper = func() corazawaf.RuleOperator

var operators = map[string]operatorsWrapper{}

func init() {
	Register("beginsWith", func() corazawaf.RuleOperator { return &beginsWith{} })
	Register("rx", func() corazawaf.RuleOperator { return &rx{} })
	Register("eq", func() corazawaf.RuleOperator { return &eq{} })
	Register("contains", func() corazawaf.RuleOperator { return &contains{} })
	Register("endsWith", func() corazawaf.RuleOperator { return &endsWith{} })
	Register("inspectFile", func() corazawaf.RuleOperator { return &inspectFile{} })
	Register("ge", func() corazawaf.RuleOperator { return &ge{} })
	Register("gt", func() corazawaf.RuleOperator { return &gt{} })
	Register("le", func() corazawaf.RuleOperator { return &le{} })
	Register("lt", func() corazawaf.RuleOperator { return &lt{} })
	Register("unconditionalMatch", func() corazawaf.RuleOperator { return &unconditionalMatch{} })
	Register("within", func() corazawaf.RuleOperator { return &within{} })
	Register("pmFromFile", func() corazawaf.RuleOperator { return &pmFromFile{} })
	Register("pm", func() corazawaf.RuleOperator { return &pm{} })
	Register("validateByteRange", func() corazawaf.RuleOperator { return &validateByteRange{} })
	Register("validateUrlEncoding", func() corazawaf.RuleOperator { return &validateURLEncoding{} })
	Register("streq", func() corazawaf.RuleOperator { return &streq{} })
	Register("ipMatch", func() corazawaf.RuleOperator { return &ipMatch{} })
	Register("ipMatchFromFile", func() corazawaf.RuleOperator { return &ipMatchFromFile{} })
	Register("ipMatchFromDataset", func() corazawaf.RuleOperator { return &ipMatchFromDataset{} })
	Register("rbl", func() corazawaf.RuleOperator { return &rbl{} })
	Register("validateUtf8Encoding", func() corazawaf.RuleOperator { return &validateUtf8Encoding{} })
	Register("noMatch", func() corazawaf.RuleOperator { return &noMatch{} })
	Register("validateNid", func() corazawaf.RuleOperator { return &validateNid{} })
	Register("geoLookup", func() corazawaf.RuleOperator { return &geoLookup{} })
	Register("detectSQLi", func() corazawaf.RuleOperator { return &detectSQLi{} })
	Register("detectXSS", func() corazawaf.RuleOperator { return &detectXSS{} })
}

// Get returns an operator by name
func Get(name string) (corazawaf.RuleOperator, error) {
	if op, ok := operators[name]; ok {
		return op(), nil
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// Register registers a new operator
// If the operator already exists it will be overwritten
func Register(name string, op func() corazawaf.RuleOperator) {
	operators[name] = op
}
