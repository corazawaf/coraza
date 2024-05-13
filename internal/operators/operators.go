// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var operators = map[string]plugintypes.OperatorFactory{}

// Get returns an operator by name
func Get(name string, options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	if op, ok := operators[name]; ok {
		return op(options)
	}
	return nil, fmt.Errorf("operator %s not found", name)
}

// Register registers a new operator
// If the operator already exists it will be overwritten
func Register(name string, op plugintypes.OperatorFactory) {
	operators[name] = op
}

func init() {
	Register("beginsWith", newBeginsWith)
	Register("contains", newContains)
	Register("detectSQLi", newDetectSQLi)
	Register("detectXSS", newDetectXSS)
	Register("endsWith", newEndsWith)
	Register("eq", newEq)
	Register("ge", newGE)
	Register("geoLookup", newGeoLookup)
	Register("gt", newGT)
	Register("inspectFile", newInspectFile)
	Register("inspectFile", newInspectFile)
	Register("ipMatch", newIPMatch)
	Register("ipMatchFromDataset", newIPMatchFromDataset)
	Register("ipMatchFromFile", newIPMatchFromFile)
	Register("le", newLE)
	Register("lt", newLT)
	Register("noMatch", newNoMatch)
	Register("pm", newPM)
	Register("pmFromDataset", newPMFromDataset)
	Register("pmFromFile", newPMFromFile)
	Register("rbl", newRBL)
	Register("rbl", newRBL)
	Register("restpath", newRESTPath)
	Register("rx", newRX)
	Register("streq", newStrEq)
	Register("unconditionalMatch", newUnconditionalMatch)
	Register("validateByteRange", newValidateByteRange)
	Register("validateNid", newValidateNID)
	Register("validateUrlEncoding", newValidateURLEncoding)
	Register("validateUtf8Encoding", newValidateUTF8Encoding)
	Register("within", newWithin)
}
