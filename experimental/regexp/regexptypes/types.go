// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package regexptypes

import "regexp"

// Regexp is the interface that wraps the basic MatchString, FindStringSubmatch,
// FindAllStringSubmatch, SubexpNames, Match and String methods.
type Regexp interface {
	MatchString(s string) bool
	FindStringSubmatch(s string) []string
	FindAllStringSubmatch(s string, n int) [][]string
	SubexpNames() []string
	Match(s []byte) bool
	String() string
}

var _ Regexp = (*regexp.Regexp)(nil)
