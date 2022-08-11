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

// CollectionSizeProxy are used to connect the size
// of many collection map values and return the sum
type CollectionSizeProxy struct {
	data     []*CollectionMap
	name     string
	variable variables.RuleVariable
}

// FindRegex returns a slice of MatchData for the regex
func (c *CollectionSizeProxy) FindRegex(key *regexp.Regexp) []types.MatchData {
	return c.FindAll()
}

// FindString returns a slice of MatchData for the string
func (c *CollectionSizeProxy) FindString(key string) []types.MatchData {
	return c.FindAll()
}

func (c *CollectionSizeProxy) FindAll() []types.MatchData {
	return []types.MatchData{
		{
			VariableName: c.name,
			Variable:     c.variable,
			Value:        strconv.FormatInt(c.Size(), 10),
		},
	}
}

func (c *CollectionSizeProxy) Size() int64 {
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
func (c *CollectionSizeProxy) Name() string {
	return c.name
}

// Reset the current CollectionSizeProxy
func (c *CollectionSizeProxy) Reset() {
	// do nothing
}

var _ Collection = &CollectionSizeProxy{}

func NewCollectionSizeProxy(variable variables.RuleVariable, data ...*CollectionMap) *CollectionSizeProxy {
	return &CollectionSizeProxy{
		name:     variable.Name(),
		variable: variable,
		data:     data,
	}
}
