// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.restpath

package operators

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/memoize"
)

var rePathTokenRe = regexp.MustCompile(`\{([^\}]+)\}`)

// Description:
// Takes a path expression with placeholders and transforms it to a regex for REST endpoint validation.
// Extracts path parameters from the URI and stores them in ARGS_PATH collection for use in rules.
// Useful for validating REST API endpoints with dynamic path segments.
//
// Arguments:
// Path template with {placeholder} syntax (e.g., "/api/v1/users/{id}/posts/{postId}").
// Placeholders are converted to named capture groups and stored as ARGS_PATH variables.
//
// Returns:
// true if the URI matches the path template, false otherwise. Matched placeholders are available in ARGS_PATH.
//
// Example:
// ```
// # Match REST endpoint and extract path parameters
// SecRule REQUEST_URI "@restpath /api/v1/users/{userId}/posts/{postId}" "id:201,pass,log"
//
// # Validate extracted path parameter
// SecRule ARGS_PATH:userId "@rx ^[0-9]+$" "id:202,deny,msg:'Invalid user ID format'"
// ```
type restpath struct {
	re *regexp.Regexp
}

var _ plugintypes.Operator = (*restpath)(nil)

func newRESTPath(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := strings.ReplaceAll(options.Arguments, "/", "\\/")
	for _, token := range rePathTokenRe.FindAllStringSubmatch(data, -1) {
		data = strings.Replace(data, token[0], fmt.Sprintf("(?P<%s>[^?/]+)", token[1]), 1)
	}

	re, err := memoize.Do(data, func() (any, error) { return regexp.Compile(data) })
	if err != nil {
		return nil, err
	}
	return &restpath{re: re.(*regexp.Regexp)}, nil
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
