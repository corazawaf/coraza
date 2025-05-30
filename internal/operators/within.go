// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.within

package operators

import (
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/macro"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type within struct {
	data []macro.Macro
}

// Description: Returns true if the input value (the needle) is found anywhere within the @within parameter
// (the haystack). Macro expansion is performed on the parameter string before comparison.
// ---
// ```apache
// # Detect request methods other than GET, POST and HEAD
// SecRule REQUEST_METHOD "!@within GET,POST,HEAD"
// ```
// Note: There are no delimiters for this operator, it is therefore often necessary to artificially impose some;
// this can be done using setvar. For instance in the example below, without the imposed delimiters (of '/') this
// rule would also match on the 'range' header (along with many other combinations), since 'range' is within the
// provided parameter. With the imposed delimiters, the rule would check for '/range/' when the range header is
// provided, and therefore would not match since '/range/ is not part of the @within parameter.
// ```apache
// SecRule REQUEST_HEADERS_NAMES "@rx ^.*$" \
// "chain,\
// id:1,\
// block,\
// t:lowercase,\
// setvar:'tx.header_name=/%{tx.0}/'"
//    SecRule TX:header_name "@within /proxy/ /lock-token/ /content-range/ /translate/ /if/" "t:none"
// ```

func newWithin(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	args := strings.Split(options.Arguments, ",")
	haystack := make([]macro.Macro, 0, len(args))
	for _, arg := range args {
		m, err := macro.NewMacro(arg)
		if err != nil {
			return nil, err
		}
		haystack = append(haystack, m)
	}

	return &within{data: haystack}, nil
}

func (o *within) Evaluate(tx plugintypes.TransactionState, value string) bool {
	for _, h := range o.data {
		if value == h.Expand(tx) {
			return true
		}
	}
	return false
}

func init() {
	Register("within", newWithin)
}
