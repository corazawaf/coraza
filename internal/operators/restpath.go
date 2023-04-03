// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.restpath

package operators

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var rePathTokenRe = regexp.MustCompile(`\{([^\}]+)\}`)

// @restpath takes as argument a path expression in the format
// /path/to/resource/{id}/{name}/{age}
// It will later transform the path to a regex and assign the variables to
// ARGS_PATH
type restpath struct {
	re *regexp.Regexp
}

var _ plugintypes.Operator = (*restpath)(nil)

func newRESTPath(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := strings.ReplaceAll(options.Arguments, "/", "\\/")
	for _, token := range rePathTokenRe.FindAllStringSubmatch(data, -1) {
		data = strings.Replace(data, token[0], fmt.Sprintf("(?P<%s>.*)", token[1]), 1)
	}
	re, err := regexp.Compile(data)
	if err != nil {
		return nil, err
	}
	return &restpath{re: re}, nil
}

func (o *restpath) Evaluate(tx plugintypes.TransactionState, value string) bool {
	// we use the re regex to match the path and match named captured groups
	// to the ARGS_PATH
	match := o.re.FindStringSubmatch(value)
	if len(match) == 0 {
		return false
	}
	for i, m := range o.re.SubexpNames() {
		if i != 0 && m != "" {
			tx.Variables().ArgsPath().SetIndex(m, 0, match[i])
		}
	}
	return true
}

func init() {
	Register("restpath", newRESTPath)
}
