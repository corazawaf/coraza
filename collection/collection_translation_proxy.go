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
	r1 := c.data1.FindRegex(key)
	r2 := c.data2.FindRegex(key)
	return append(r1, r2...)
}

// FindString returns a slice of MatchData for the string
func (c *CollectionTranslationProxy) FindString(key string) []types.MatchData {
	r1 := c.data1.FindString(key)
	r2 := c.data2.FindString(key)
	return append(r1, r2...)
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
	res := &CollectionTranslationProxy{
		name:     variable.Name(),
		variable: variable,
		data1:    c1,
	}
	res.data2 = c2
	return res
}
