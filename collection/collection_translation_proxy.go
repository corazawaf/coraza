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

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// CollectionTranslationProxy are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionTranslationProxys ARE NOT concurrent safe
type CollectionTranslationProxy struct {
	data1    *CollectionMap
	data2    *CollectionMap
	name     string
	variable variables.RuleVariable
}

// FindRegex returns a slice of MatchData for the regex
func (c *CollectionTranslationProxy) FindRegex(key *regexp.Regexp) []types.MatchData {
	res := []types.MatchData{}
	keys := c.data1.keysRx(key)
	if c.data2 != nil {
		keys = append(keys, c.data2.keysRx(key)...)
	}
	for _, k := range keys {
		res = append(res, types.MatchData{
			VariableName: c.name,
			Variable:     c.variable,
			Value:        k,
		})
	}
	return res
}

// FindString returns a slice of MatchData for the string
func (c *CollectionTranslationProxy) FindString(key string) []types.MatchData {
	c1 := len(c.data1.Get(key))
	if c.data2 == nil && c1 == 0 {
		return []types.MatchData{}
	}
	var c2 int
	if c.data2 != nil {
		c2 = len(c.data2.Get(key))
	}
	if c1+c2 > 0 {
		return []types.MatchData{
			{
				VariableName: c.name,
				Variable:     c.variable,
				Value:        key,
			},
		}
	}
	return nil
}

func (c *CollectionTranslationProxy) FindAll() []types.MatchData {
	keys := c.data1.keys()
	if c.data2 != nil {
		keys = append(keys, c.data2.keys()...)
	}
	res := []types.MatchData{}
	for _, k := range keys {
		res = append(res, types.MatchData{
			VariableName: c.name,
			Variable:     c.variable,
			Value:        k,
		})
	}
	return res
}

// Name returns the name for the current CollectionTranslationProxy
func (c *CollectionTranslationProxy) Name() string {
	return c.name
}

// Reset the current CollectionTranslationProxy
func (c *CollectionTranslationProxy) Reset() {
	// do nothing
}

var _ Collection = &CollectionTranslationProxy{}

func NewCollectionTranslationProxy(variable variables.RuleVariable, c1 *CollectionMap, c2 *CollectionMap) *CollectionTranslationProxy {
	return &CollectionTranslationProxy{
		name:     variable.Name(),
		variable: variable,
		data1:    c1,
		data2:    c2,
	}
}
