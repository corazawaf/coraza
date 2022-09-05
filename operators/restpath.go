// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

var rePathTokenRe = regexp.MustCompile(`\{([^\}]+)\}`)

// @restpath takes as argument a path expression in the format
// /path/to/resource/{id}/{name}/{age}
// It will later transform the path to a regex and assign the variables to
// ARGS_PATH
type restpath struct {
	re *regexp.Regexp
}

func (o *restpath) Init(options corazawaf.RuleOperatorOptions) error {
	data := strings.ReplaceAll(options.Arguments, "/", "\\/")
	for _, token := range rePathTokenRe.FindAllStringSubmatch(data, -1) {
		data = strings.Replace(data, token[0], fmt.Sprintf("(?P<%s>.*)", token[1]), 1)
	}
	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *restpath) Evaluate(tx *corazawaf.Transaction, value string) bool {
	// we use the re regex to match the path and match named captured groups
	// to the ARGS_PATH
	match := o.re.FindStringSubmatch(value)
	if len(match) == 0 {
		return false
	}
	for i, m := range o.re.SubexpNames() {
		if i != 0 && m != "" {
			tx.Variables.ArgsPath.SetIndex(m, 0, match[i])
		}
	}
	return true
}

var _ corazawaf.RuleOperator = &restpath{}

func init() {
	Register("restpath", func() corazawaf.RuleOperator {
		return &restpath{}
	})
}
