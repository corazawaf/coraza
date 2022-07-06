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

// CollectionMap are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type CollectionMap struct {
	data     map[string][]types.AnchoredVar
	name     string
	variable variables.RuleVariable
}

// Get returns a slice of strings for a key
func (c *CollectionMap) Get(key string) []string {
	values := []string{}
	for _, a := range c.data[strings.ToLower(key)] {
		values = append(values, a.Value)
	}
	return values
}

// FindRegex returns a slice of MatchData for the regex
func (c *CollectionMap) FindRegex(key *regexp.Regexp) []types.MatchData {
	result := []types.MatchData{}
	for k, data := range c.data {
		if key.MatchString(k) {
			for _, d := range data {
				result = append(result, types.MatchData{
					VariableName: c.name,
					Variable:     c.variable,
					Key:          d.Name,
					Value:        d.Value,
				})
			}
		}
	}
	return result
}

// FindString returns a slice of MatchData for the string
func (c *CollectionMap) FindString(key string) []types.MatchData {
	result := []types.MatchData{}
	if key == "" {
		for _, data := range c.data {
			for _, d := range data {
				result = append(result, types.MatchData{
					VariableName: c.name,
					Variable:     c.variable,
					Key:          d.Name,
					Value:        d.Value,
				})
			}
		}
		return result
	}
	// if key is not empty
	if e, ok := c.data[key]; ok {
		for _, aVar := range e {
			result = append(result, types.MatchData{
				VariableName: c.name,
				Variable:     c.variable,
				Key:          aVar.Name,
				Value:        aVar.Value,
			})
		}
	}
	return result

}

func (c *CollectionMap) String() string {
	return ""
}

func (c *CollectionMap) Int64() int64 {
	return 0
}

func (c *CollectionMap) Int() int {
	return 0
}

// AddCS a value to some key with case sensitive vKey
func (c *CollectionMap) AddCS(key string, vKey string, vVal string) {
	aVal := types.AnchoredVar{Name: vKey, Value: vVal}
	c.data[key] = append(c.data[key], aVal)
}

// Add a value to some key
func (c *CollectionMap) Add(key string, value string) {
	c.AddCS(key, key, value)
}

// AddUniqueCS will add a value to a key if it is not already there
// with case sensitive vKey
func (c *CollectionMap) AddUniqueCS(key string, vKey string, vVal string) {
	if c.data[key] == nil {
		c.AddCS(key, vKey, vVal)
		return
	}

	for _, a := range c.data[key] {
		if a.Value == vVal {
			return
		}
	}
	c.AddCS(key, vKey, vVal)
}

// AddUnique will add a value to a key if it is not already there
func (c *CollectionMap) AddUnique(key string, value string) {
	c.AddUniqueCS(key, key, value)
}

// SetCS will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
// with case sensitive vKey
func (c *CollectionMap) SetCS(key string, vKey string, values []string) {
	c.data[key] = []types.AnchoredVar{}
	for _, v := range values {
		c.data[key] = append(c.data[key],
			types.AnchoredVar{Name: vKey, Value: v})
	}
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *CollectionMap) Set(key string, values []string) {
	c.SetCS(key, key, values)
}

// SetIndexCS will place the value under the index
// If the index is higher than the current size of the CollectionMap
// it will be appended
// with case sensitive vKey
func (c *CollectionMap) SetIndexCS(key string, index int, vKey string, value string) {
	if c.data[key] == nil {
		c.data[key] = []types.AnchoredVar{{Name: vKey, Value: value}}
	}
	vVal := types.AnchoredVar{Name: vKey, Value: value}
	if len(c.data[key]) <= index {
		c.data[key] = append(c.data[key], vVal)
		return
	}
	c.data[key][index] = vVal
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the CollectionMap
// it will be appended
func (c *CollectionMap) SetIndex(key string, index int, value string) {
	c.SetIndexCS(key, index, key, value)
}

// Remove deletes the key from the CollectionMap
func (c *CollectionMap) Remove(key string) {
	delete(c.data, key)
}

// Name returns the name for the current CollectionMap
func (c *CollectionMap) Name() string {
	return c.name
}

// Reset the current CollectionMap
func (c *CollectionMap) Reset() {
	// we don't reset the CollectionMap if it wasn't used, for performance reasons
	if len(c.data) == 1 && len(c.data[""]) == 0 {
		return
	}
	c.data = nil
	c.data = map[string][]types.AnchoredVar{
		"": {},
	}
}

var _ Collection = &CollectionMap{}

func NewCollectionMap(variable variables.RuleVariable) *CollectionMap {
	return &CollectionMap{
		name:     variable.Name(),
		variable: variable,
		data:     map[string][]types.AnchoredVar{},
	}
}
