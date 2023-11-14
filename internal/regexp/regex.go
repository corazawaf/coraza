// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package regexp

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/experimental/regexp/regexptypes"
)

var RegexCompiler func(expr string) (regexptypes.Regexp, error)

func init() {
	RegexCompiler = func(expr string) (regexptypes.Regexp, error) {
		return regexp.Compile(expr)
	}
}

type Regexp = regexptypes.Regexp

// MustCompile is like Compile but panics if the expression cannot be parsed.
// It is not intented to use with user input e.g. rules because it panics and
// bypasses whatever logic provided by the users for regex compilation.
func MustCompile(str string) *regexp.Regexp {
	return regexp.MustCompile(str)
}

func Compile(expr string) (regexptypes.Regexp, error) {
	return RegexCompiler(expr)
}
