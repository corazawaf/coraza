// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/rules"
)

var operators = map[string]rules.OperatorFactory{}

func init() {
	Register("beginsWith", newBeginsWith)
	Register("rx", newRX)
	Register("eq", newEq)
	Register("contains", newContains)
	Register("endsWith", newEndsWith)
	Register("inspectFile", newInspectFile)
	Register("ge", newGE)
	Register("gt", newGT)
	Register("le", newLE)
	Register("lt", newLT)
	Register("unconditionalMatch", newUnconditionalMatch)
	Register("within", newWithin)
	Register("pmFromFile", newPMFromFile)
	Register("pm", newPM)
	Register("validateByteRange", newValidateByteRange)
	Register("validateUrlEncoding", newValidateURLEncoding)
	Register("streq", newStrEq)
	Register("ipMatch", newIPMatch)
	Register("ipMatchFromFile", newIPMatchFromFile)
	Register("ipMatchFromDataset", newIPMatchFromDataset)
	Register("rbl", newRBL)
	Register("validateUtf8Encoding", newValidateUTF8Encoding)
	Register("noMatch", newNoMatch)
	Register("validateNid", newValidateNID)
	Register("geoLookup", newGeoLookup)
	Register("detectSQLi", newDetectSQLi)
	Register("detectXSS", newDetectXSS)
	Register("restpath", newRESTPath)
}

// Get returns an operator by name
func Get(name string, options rules.OperatorOptions) (rules.Operator, error) {
	if op, ok := operators[name]; ok {
		return op(options)
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// Register registers a new operator
// If the operator already exists it will be overwritten
func Register(name string, op rules.OperatorFactory) {
	operators[name] = op
}
