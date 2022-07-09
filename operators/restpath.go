// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package operators

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

var rePathTokenRe = regexp.MustCompile(`\{([^\}]+)\}`)

// @restpath takes as argument a path expression in the format
// /path/to/resource/{id}/{name}/{age}
// It will later transform the path to a regex and assign the variables to
// ARGS_PATH
type restpath struct {
	re *regexp.Regexp
}

func (o *restpath) Init(options coraza.RuleOperatorOptions) error {
	data := strings.ReplaceAll(options.Arguments, "/", "\\/")
	for _, token := range rePathTokenRe.FindAllStringSubmatch(data, -1) {
		data = strings.Replace(data, token[0], fmt.Sprintf("(?P<%s>.*)", token[1]), 1)
	}
	re, err := regexp.Compile(data)
	o.re = re
	return err
}

func (o *restpath) Evaluate(tx *coraza.Transaction, value string) bool {
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

var _ coraza.RuleOperator = &restpath{}

func init() {
	Register("restpath", func() coraza.RuleOperator {
		return &restpath{}
	})
}
