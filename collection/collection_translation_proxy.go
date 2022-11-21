// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// TranslationProxy are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionTranslationProxys ARE NOT concurrent safe
type TranslationProxy struct {
	data     []*Map
	name     string
	variable variables.RuleVariable
}

func (c *TranslationProxy) Find(query *Query) []types.MatchData {
	switch query.queryType {
	case queryTypeAll:
		return c.findAll()
	case queryTypeRegex:
		return c.findRegex(query.regex)
	case queryTypeEquals:
		return c.findString(query.exactMatch)
	}
	return nil
}

// findRegex returns a slice of MatchData for the regex
func (c *TranslationProxy) findRegex(key *regexp.Regexp) []types.MatchData {
	var res []types.MatchData
	for _, c := range c.data {
		for _, k := range c.keysRx(key) {
			res = append(res, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Value_:        k,
			})
		}
	}
	return res
}

// findString returns a slice of MatchData for the string
func (c *TranslationProxy) findString(key string) []types.MatchData {
	for _, c := range c.data {
		if len(c.Get(key)) > 0 {
			return []types.MatchData{
				&corazarules.MatchData{
					VariableName_: c.name,
					Variable_:     c.variable,
					Value_:        key,
				},
			}
		}
	}
	return nil
}

// findAll returns all keys from Proxy Collections
func (c *TranslationProxy) findAll() []types.MatchData {
	var res []types.MatchData
	for _, c := range c.data {
		for _, k := range c.keys() {
			res = append(res, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Value_:        k,
			})
		}
	}
	return res
}

// Data returns the keys of all Proxy collections
func (c *TranslationProxy) Data() []string {
	var res []string
	for _, c := range c.data {
		res = append(res, c.keys()...)
	}
	return res
}

// Name returns the name for the current CollectionTranslationProxy
func (c *TranslationProxy) Name() string {
	return c.name
}

// Reset the current CollectionTranslationProxy
func (c *TranslationProxy) Reset() {
	// do nothing
}

// Get the value for the index
func (c *TranslationProxy) Get(index int) string {
	if index < len(c.data) {
		if v := c.data[index].Get(""); len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

var _ Collection = &TranslationProxy{}

// NewTranslationProxy creates a translation proxy
// Translation proxies are used to merge variable keys from multiple collections
func NewTranslationProxy(variable variables.RuleVariable, data ...*Map) *TranslationProxy {
	return &TranslationProxy{
		name:     variable.Name(),
		variable: variable,
		data:     data,
	}
}
