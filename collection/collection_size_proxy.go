// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// SizeProxy are used to connect the size
// of many collection map values and return the sum
type SizeProxy struct {
	data     []*Map
	name     string
	variable variables.RuleVariable
}

// FindAll returns a slice of MatchData of all matches
func (c *SizeProxy) Find(_ *Query) []types.MatchData {
	return []types.MatchData{
		&corazarules.MatchData{
			VariableName_: c.name,
			Variable_:     c.variable,
			Value_:        strconv.FormatInt(c.Size(), 10),
		},
	}
}

// Size returns the size of all the collections values
func (c *SizeProxy) Size() int64 {
	i := 0
	for _, d := range c.data {
		// we iterate over d
		for _, data := range d.data {
			for _, v := range data {
				i += len(v)
			}
		}
	}
	return int64(i)
}

// Name returns the name for the current CollectionSizeProxy
func (c *SizeProxy) Name() string {
	return c.name
}

// Reset the current CollectionSizeProxy
func (c *SizeProxy) Reset() {
	// do nothing
}

var _ Collection = &SizeProxy{}

// NewCollectionSizeProxy returns a collection that
// only returns the total sum of all the collections values
func NewCollectionSizeProxy(variable variables.RuleVariable, data ...*Map) *SizeProxy {
	return &SizeProxy{
		name:     variable.Name(),
		variable: variable,
		data:     data,
	}
}
