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

// CollectionSimple are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionSimples ARE NOT concurrent safe
type CollectionSimple struct {
	data     string
	name     string
	variable variables.RuleVariable
}

// FindRegex returns a slice of MatchData for the regex
func (c *CollectionSimple) FindRegex(key *regexp.Regexp) []types.MatchData {
	return []types.MatchData{
		{
			Value: c.data,
		},
	}
}

// FindString returns a slice of MatchData for the string
func (c *CollectionSimple) FindString(key string) []types.MatchData {
	return []types.MatchData{
		{
			Value: c.data,
		},
	}
}

// GetFirstString returns the first string occurrence of a key
func (c *CollectionSimple) String() string {
	return c.data
}

// GetFirstInt64 returns the first int64 occurrence of a key
func (c *CollectionSimple) Int64() int64 {
	return int64(c.Int())
}

// GetFirstInt returns the first int occurrence of a key
func (c *CollectionSimple) Int() int {
	r, _ := strconv.ParseInt(c.data, 10, 32)
	return int(r)
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *CollectionSimple) Set(value string) {
	c.data = value
}

// Name returns the name for the current CollectionSimple
func (c *CollectionSimple) Name() string {
	return c.name
}

// Reset the current CollectionSimple
func (c *CollectionSimple) Reset() {
	c.data = ""
}

var _ Collection = &CollectionSimple{}

func NewCollectionSimple(variable variables.RuleVariable) *CollectionSimple {
	return &CollectionSimple{
		variable: variable,
		name:     variable.Name(),
	}
}
