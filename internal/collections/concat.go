// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type ConcatCollection struct {
	data     []collection.Collection
	name     string
	variable variables.RuleVariable
}

var _ collection.Collection = &ConcatCollection{}

func NewConcatCollection(variable variables.RuleVariable, data ...collection.Collection) *ConcatCollection {
	return &ConcatCollection{
		data:     data,
		name:     variable.Name(),
		variable: variable,
	}
}

// FindRegex returns a slice of MatchData for the regex
func (c *ConcatCollection) FindRegex(key *regexp.Regexp) []types.MatchData {
	var res []types.MatchData
	for _, c := range c.data {
		res = append(res, c.FindRegex(key)...)
	}
	return res
}

// FindString returns a slice of MatchData for the string
func (c *ConcatCollection) FindString(key string) []types.MatchData {
	var res []types.MatchData
	for _, c := range c.data {
		res = append(res, c.FindString(key)...)
	}
	return res
}

// FindAll returns all matches for all collections
func (c *ConcatCollection) FindAll() []types.MatchData {
	var res []types.MatchData
	for _, c := range c.data {
		res = append(res, c.FindAll()...)
	}
	return res
}

// Name returns the name for the current CollectionconcatCollection
func (c *ConcatCollection) Name() string {
	return c.name
}

// Reset the current ConcatCollection
func (c *ConcatCollection) Reset() {
}
