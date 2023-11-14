// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/regexp"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type SizeCollection struct {
	data     []*NamedCollection
	variable variables.RuleVariable
}

var _ collection.Collection = &SizeCollection{}

// NewSizeCollection returns a collection that
// only returns the total sum of all the collections values
func NewSizeCollection(variable variables.RuleVariable, data ...*NamedCollection) *SizeCollection {
	return &SizeCollection{
		variable: variable,
		data:     data,
	}
}

// FindRegex returns a slice of MatchData for the regex
func (c *SizeCollection) FindRegex(regexp.Regexp) []types.MatchData {
	return c.FindAll()
}

// FindString returns a slice of MatchData for the string
func (c *SizeCollection) FindString(string) []types.MatchData {
	return c.FindAll()
}

// FindAll returns a slice of MatchData of all matches
func (c *SizeCollection) FindAll() []types.MatchData {
	return []types.MatchData{
		&corazarules.MatchData{
			Variable_: c.variable,
			Value_:    strconv.Itoa(c.size()),
		},
	}
}

// Name returns the name for the current CollectionSizeProxy
func (c *SizeCollection) Name() string {
	return c.variable.Name()
}

func (c *SizeCollection) Format(res *strings.Builder) {
	res.WriteString(c.variable.Name())
	res.WriteString(": ")
	res.WriteString(strconv.Itoa(c.size()))
}

func (c *SizeCollection) String() string {
	return fmt.Sprintf("%s: %d", c.variable.Name(), c.size())
}

// Size returns the size of all the collections values
func (c *SizeCollection) size() int {
	i := 0
	for _, d := range c.data {
		// we iterate over d
		for _, data := range d.data {
			for _, v := range data {
				i += len(v.key) + len(v.value)
			}
		}
	}
	return i
}
