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
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func iterateProxy(keyRx *regexp.Regexp, keyStr string, data map[string][]types.AnchoredVar, variableName string, variable variables.RuleVariable, regex bool) []types.MatchData {
	result := []types.MatchData{}
	for k, data := range data {
		if (regex && keyRx.MatchString(k)) || (!regex && keyStr == "") || (!regex && k == keyStr) {
			for _, d := range data {
				result = append(result, types.MatchData{
					VariableName: variableName,
					Variable:     variable,
					Key:          d.Name,
					Value:        d.Value,
				})
			}
		}
	}
	return result
}

// CollectionProxy are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionProxys ARE NOT concurrent safe
type CollectionProxy struct {
	data1    map[string][]types.AnchoredVar
	data2    map[string][]types.AnchoredVar
	name     string
	variable variables.RuleVariable
}

// Get returns a slice of strings for a key
func (c *CollectionProxy) Get(key string) []string {
	values := []string{}
	for _, a := range c.data1[strings.ToLower(key)] {
		values = append(values, a.Value)
	}
	for _, a := range c.data2[strings.ToLower(key)] {
		values = append(values, a.Value)
	}
	return values
}

// FindRegex returns a slice of MatchData for the regex
func (c *CollectionProxy) FindRegex(key *regexp.Regexp) []types.MatchData {
	result := iterateProxy(key, "", c.data1, c.name, c.variable, true)
	return append(result, iterateProxy(key, "", c.data2, c.name, c.variable, true)...)
}

// FindString returns a slice of MatchData for the string
func (c *CollectionProxy) FindString(key string) []types.MatchData {
	result := iterateProxy(nil, "", c.data1, c.name, c.variable, false)
	return append(result, iterateProxy(nil, "", c.data2, c.name, c.variable, false)...)

}

// GetFirstString returns the first string occurrence of a key
func (c *CollectionProxy) String() string {
	return ""
}

// GetFirstInt64 returns the first int64 occurrence of a key
func (c *CollectionProxy) Int64() int64 {
	return 0
}

// GetFirstInt returns the first int occurrence of a key
func (c *CollectionProxy) Int() int {
	return 0
}

// AddCS a value to some key with case sensitive vKey
func (c *CollectionProxy) AddCS(key string, vKey string, vVal string) {
	// Not implemented
}

// Add a value to some key
func (c *CollectionProxy) Add(key string, value string) {
	// Not implemented
}

// AddUniqueCS will add a value to a key if it is not already there
// with case sensitive vKey
func (c *CollectionProxy) AddUniqueCS(key string, vKey string, vVal string) {
	// Not implemented
}

// AddUnique will add a value to a key if it is not already there
func (c *CollectionProxy) AddUnique(key string, value string) {
	// Not implemented
}

// SetCS will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
// with case sensitive vKey
func (c *CollectionProxy) SetCS(key string, vKey string, values []string) {
	// Not implemented
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *CollectionProxy) Set(key string, values []string) {
	// Not implemented
}

// SetIndexCS will place the value under the index
// If the index is higher than the current size of the CollectionProxy
// it will be appended
// with case sensitive vKey
func (c *CollectionProxy) SetIndexCS(key string, index int, vKey string, value string) {
	// Not implemented
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the CollectionProxy
// it will be appended
func (c *CollectionProxy) SetIndex(key string, index int, value string) {
	// Not implemented
}

// Remove deletes the key from the CollectionProxy
func (c *CollectionProxy) Remove(key string) {
	// Not implemented
}

// Name returns the name for the current CollectionProxy
func (c *CollectionProxy) Name() string {
	return c.name
}

// Reset the current CollectionProxy
func (c *CollectionProxy) Reset() {
	for k := range c.data1 {
		delete(c.data1, k)
	}
	for k := range c.data2 {
		delete(c.data2, k)
	}
}

var _ Collection = &CollectionProxy{}

func NewCollectionProxy(variable variables.RuleVariable, c1 Collection, c2 Collection) Collection {
	c1Map := (c1).(*CollectionMap)
	c2Map := (c2).(*CollectionMap)
	return &CollectionProxy{
		name:     variable.Name(),
		variable: variable,
		data1:    c1Map.data,
		data2:    c2Map.data,
	}
}
