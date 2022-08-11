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

package collection

import (
	"regexp"
	"strconv"

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

// FindRegex returns a slice of MatchData for the regex
func (c *SizeProxy) FindRegex(key *regexp.Regexp) []types.MatchData {
	return c.FindAll()
}

// FindString returns a slice of MatchData for the string
func (c *SizeProxy) FindString(key string) []types.MatchData {
	return c.FindAll()
}

// FindAll returns a slice of MatchData of all matches
func (c *SizeProxy) FindAll() []types.MatchData {
	return []types.MatchData{
		{
			VariableName: c.name,
			Variable:     c.variable,
			Value:        strconv.FormatInt(c.Size(), 10),
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
				i += len(v.Value)
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
