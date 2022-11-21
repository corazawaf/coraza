// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import "regexp"

type queryType int

const (
	queryTypeAll queryType = iota
	queryTypeRegex
	queryTypeEquals
)

type Query struct {
	queryType  queryType
	regex      *regexp.Regexp
	exactMatch string
}

func NewQueryAll() *Query {
	return &Query{
		queryType: queryTypeAll,
	}
}

func NewQueryRegex(regex *regexp.Regexp) *Query {
	return &Query{
		queryType: queryTypeRegex,
		regex:     regex,
	}
}

func NewQueryEquals(exactMatch string) *Query {
	return &Query{
		queryType:  queryTypeEquals,
		exactMatch: exactMatch,
	}
}
