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

// CollectionProxy are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionProxys ARE NOT concurrent safe
type CollectionProxy struct {
	data     []*CollectionMap
	name     string
	variable variables.RuleVariable
}

// FindRegex returns a slice of MatchData for the regex
func (c *CollectionProxy) FindRegex(key *regexp.Regexp) []types.MatchData {
	res := []types.MatchData{}
	for _, c := range c.data {
		res = append(res, c.FindRegex(key)...)
	}
	return res
}

// FindString returns a slice of MatchData for the string
func (c *CollectionProxy) FindString(key string) []types.MatchData {
	res := []types.MatchData{}
	for _, c := range c.data {
		res = append(res, c.FindString(key)...)
	}
	return res
}

func (c *CollectionProxy) FindAll() []types.MatchData {
	res := []types.MatchData{}
	for _, c := range c.data {
		res = append(res, c.FindAll()...)
	}
	return res
}

// Name returns the name for the current CollectionProxy
func (c *CollectionProxy) Name() string {
	return c.name
}

// Get returns the data for the key
func (c *CollectionProxy) Get(key string) []string {
	res := []string{}
	for _, c := range c.data {
		res = append(res, c.Get(key)...)
	}
	return res
}

// Data returns merged data from all CollectionMap
func (c *CollectionProxy) Data() map[string][]string {
	res := map[string][]string{}
	for _, c := range c.data {
		for k, v := range c.Data() {
			res[k] = append(res[k], v...)
		}
	}
	return res
}

// Reset the current CollectionProxy
func (c *CollectionProxy) Reset() {
}

var _ Collection = &CollectionProxy{}

func NewCollectionProxy(variable variables.RuleVariable, data ...*CollectionMap) *CollectionProxy {
	return &CollectionProxy{
		name:     variable.Name(),
		variable: variable,
		data:     data,
	}
}
