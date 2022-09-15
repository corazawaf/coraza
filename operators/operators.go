// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/rules"
)

type operatorsWrapper = func() rules.Operator

var operators = map[string]operatorsWrapper{}

func init() {
	Register("beginsWith", func() rules.Operator { return &beginsWith{} })
	Register("rx", func() rules.Operator { return &rx{} })
	Register("eq", func() rules.Operator { return &eq{} })
	Register("contains", func() rules.Operator { return &contains{} })
	Register("endsWith", func() rules.Operator { return &endsWith{} })
	Register("inspectFile", func() rules.Operator { return &inspectFile{} })
	Register("ge", func() rules.Operator { return &ge{} })
	Register("gt", func() rules.Operator { return &gt{} })
	Register("le", func() rules.Operator { return &le{} })
	Register("lt", func() rules.Operator { return &lt{} })
	Register("unconditionalMatch", func() rules.Operator { return &unconditionalMatch{} })
	Register("within", func() rules.Operator { return &within{} })
	Register("pmFromFile", func() rules.Operator { return &pmFromFile{} })
	Register("pm", func() rules.Operator { return &pm{} })
	Register("validateByteRange", func() rules.Operator { return &validateByteRange{} })
	Register("validateUrlEncoding", func() rules.Operator { return &validateURLEncoding{} })
	Register("streq", func() rules.Operator { return &streq{} })
	Register("ipMatch", func() rules.Operator { return &ipMatch{} })
	Register("ipMatchFromFile", func() rules.Operator { return &ipMatchFromFile{} })
	Register("ipMatchFromDataset", func() rules.Operator { return &ipMatchFromDataset{} })
	Register("rbl", func() rules.Operator { return &rbl{} })
	Register("validateUtf8Encoding", func() rules.Operator { return &validateUtf8Encoding{} })
	Register("noMatch", func() rules.Operator { return &noMatch{} })
	Register("validateNid", func() rules.Operator { return &validateNid{} })
	Register("geoLookup", func() rules.Operator { return &geoLookup{} })
	Register("detectSQLi", func() rules.Operator { return &detectSQLi{} })
	Register("detectXSS", func() rules.Operator { return &detectXSS{} })
}

// Get returns an operator by name
func Get(name string) (rules.Operator, error) {
	if op, ok := operators[name]; ok {
		return op(), nil
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// Register registers a new operator
// If the operator already exists it will be overwritten
func Register(name string, op func() rules.Operator) {
	operators[name] = op
}
