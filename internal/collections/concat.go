// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// ConcatCollection is a collection view over multiple collections.
type ConcatCollection struct {
	data     []collection.Collection
	variable variables.RuleVariable
}

var _ collection.Collection = &ConcatCollection{}

func NewConcatCollection(variable variables.RuleVariable, data ...collection.Collection) *ConcatCollection {
	return &ConcatCollection{
		data:     data,
		variable: variable,
	}
}

// FindAll returns all matches for all collections
func (c *ConcatCollection) FindAll() []types.MatchData {
	var res []types.MatchData
	for _, d := range c.data {
		res = concat(res, replaceVariable(c.variable, d.FindAll()))
	}
	return res
}

// concat appends more to res, adopting more as the result when nothing was
// collected yet: a sub-collection's fresh FindAll slice is ours to keep, and
// for the common case of a single non-empty sub-collection (ARGS on a GET
// request) that saves re-allocating and copying every element.
func concat(res, more []types.MatchData) []types.MatchData {
	if res == nil {
		return more
	}
	return append(res, more...)
}

// Name returns the name for the current CollectionconcatCollection
func (c *ConcatCollection) Name() string {
	return c.variable.Name()
}

// ConcatKeyed is a collection view over multiple keyed collections.
type ConcatKeyed struct {
	data     []collection.Keyed
	variable variables.RuleVariable
}

var _ collection.Keyed = &ConcatKeyed{}

func NewConcatKeyed(variable variables.RuleVariable, data ...collection.Keyed) *ConcatKeyed {
	return &ConcatKeyed{
		data:     data,
		variable: variable,
	}
}

func (c *ConcatKeyed) Get(key string) []string {
	keyL := strings.ToLower(key)
	var res []string
	for _, c := range c.data {
		res = append(res, c.Get(keyL)...)
	}
	return res
}

// First returns the first value stored under key across the collections.
func (c *ConcatKeyed) First(key string) (string, bool) {
	keyL := strings.ToLower(key)
	for _, d := range c.data {
		if f, ok := d.(interface{ First(string) (string, bool) }); ok {
			if v, ok := f.First(keyL); ok {
				return v, true
			}
			continue
		}
		if v := d.Get(keyL); len(v) > 0 {
			return v[0], true
		}
	}
	return "", false
}

// FindRegex returns a slice of MatchData for the regex
func (c *ConcatKeyed) FindRegex(key *regexp.Regexp) []types.MatchData {
	var res []types.MatchData
	for _, d := range c.data {
		res = concat(res, replaceVariable(c.variable, d.FindRegex(key)))
	}
	return res
}

// FindString returns a slice of MatchData for the string
func (c *ConcatKeyed) FindString(key string) []types.MatchData {
	var res []types.MatchData
	for _, d := range c.data {
		res = concat(res, replaceVariable(c.variable, d.FindString(key)))
	}
	return res
}

// FindAll returns all matches for all collections
func (c *ConcatKeyed) FindAll() []types.MatchData {
	var res []types.MatchData
	for _, d := range c.data {
		res = concat(res, replaceVariable(c.variable, d.FindAll()))
	}
	return res
}

// Name returns the name for the current CollectionconcatCollection
func (c *ConcatKeyed) Name() string {
	return c.variable.Name()
}

// replaceVariable ensures a returned match references the variable of a concatenated variable,
// not original one.
func replaceVariable(v variables.RuleVariable, md []types.MatchData) []types.MatchData {
	for _, m := range md {
		switch m := m.(type) {
		case *corazarules.VariableMatch:
			m.Variable_ = v
		case *corazarules.MatchData:
			m.Variable_ = v
		}
	}
	return md
}
