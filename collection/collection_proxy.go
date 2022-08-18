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

// Proxy are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionProxys ARE NOT concurrent safe
type Proxy struct {
	data     []*Map
	name     string
	variable variables.RuleVariable
}

// FindRegex returns a slice of MatchData for the regex
func (c *Proxy) FindRegex(key *regexp.Regexp) []types.MatchData {
	res := []types.MatchData{}
	for _, c := range c.data {
		res = append(res, c.FindRegex(key)...)
	}
	return res
}

// FindString returns a slice of MatchData for the string
func (c *Proxy) FindString(key string) []types.MatchData {
	res := []types.MatchData{}
	for _, c := range c.data {
		res = append(res, c.FindString(key)...)
	}
	return res
}

// FindAll returns all matches for all collections
func (c *Proxy) FindAll() []types.MatchData {
	res := []types.MatchData{}
	for _, c := range c.data {
		res = append(res, c.FindAll()...)
	}
	return res
}

// Name returns the name for the current CollectionProxy
func (c *Proxy) Name() string {
	return c.name
}

// Get returns the data for the key
func (c *Proxy) Get(key string) []string {
	res := []string{}
	for _, c := range c.data {
		res = append(res, c.Get(key)...)
	}
	return res
}

// Data returns merged data from all CollectionMap
func (c *Proxy) Data() map[string][]string {
	res := map[string][]string{}
	for _, c := range c.data {
		for k, v := range c.Data() {
			res[k] = append(res[k], v...)
		}
	}
	return res
}

// Reset the current CollectionProxy
func (c *Proxy) Reset() {
}

var _ Collection = &Proxy{}

// NewProxy returns a Proxy collection that merges all collections
func NewProxy(variable variables.RuleVariable, data ...*Map) *Proxy {
	return &Proxy{
		name:     variable.Name(),
		variable: variable,
		data:     data,
	}
}
