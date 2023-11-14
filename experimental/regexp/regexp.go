// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/regexp/regexptypes"
	"github.com/corazawaf/coraza/v3/internal/regexp"
)

// SetRegexpCompiler sets the regex compiler used by the WAF. This is specially
// useful when we want to lazily compile regexes in a mono thread environment as
// we don't need to synchronize the regex compilation.
func SetRegexpCompiler(fn func(expr string) (regexptypes.Regexp, error)) {
	if fn == nil {
		fmt.Println("invalid regex compiler")
		return
	}

	if regexp.RegexCompiler != nil {
		fmt.Println("regex compiler already set")
		return
	}

	regexp.RegexCompiler = fn
}
