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

package coraza

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Collection are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: Collections ARE NOT concurrent safe
type Collection struct {
	data     map[string][]types.AnchoredVar
	name     string
	variable variables.RuleVariable
}

// Get returns a slice of strings for a key
func (c *Collection) Get(key string) []string {
	values := []string{}
	for _, a := range c.data[strings.ToLower(key)] {
		values = append(values, a.Value)
	}
	return values
}

// FindRegex returns a slice of MatchData for the regex
func (c *Collection) FindRegex(key *regexp.Regexp) []MatchData {
	result := []MatchData{}
	for k, data := range c.data {
		if key.MatchString(k) {
			for _, d := range data {
				result = append(result, MatchData{
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
func (c *Collection) FindString(key string) []MatchData {
	result := []MatchData{}
	if key == "" {
		for _, data := range c.data {
			for _, d := range data {
				result = append(result, MatchData{
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
			result = append(result, MatchData{
				VariableName: c.name,
				Variable:     c.variable,
				Key:          aVar.Name,
				Value:        aVar.Value,
			})
		}
	}
	return result

}

// GetFirstString returns the first string occurrence of a key
func (c *Collection) GetFirstString(key string) string {
	if a, ok := c.data[key]; ok && len(a) > 0 {
		return a[0].Value
	}
	return ""
}

// GetFirstInt64 returns the first int64 occurrence of a key
func (c *Collection) GetFirstInt64(key string) int64 {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.ParseInt(a[0].Value, 10, 64)
		return i
	}
	return 0
}

// GetFirstInt returns the first int occurrence of a key
func (c *Collection) GetFirstInt(key string) int {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.Atoi(a[0].Value)
		return i
	}
	return 0
}

// AddCS a value to some key with case sensitive vKey
func (c *Collection) AddCS(key string, vKey string, vVal string) {
	aVal := types.AnchoredVar{Name: vKey, Value: vVal}
	c.data[key] = append(c.data[key], aVal)
}

// Add a value to some key
func (c *Collection) Add(key string, value string) {
	c.AddCS(key, key, value)
}

// AddUniqueCS will add a value to a key if it is not already there
// with case sensitive vKey
func (c *Collection) AddUniqueCS(key string, vKey string, vVal string) {
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
func (c *Collection) AddUnique(key string, value string) {
	c.AddUniqueCS(key, key, value)
}

// SetCS will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
// with case sensitive vKey
func (c *Collection) SetCS(key string, vKey string, values []string) {
	c.data[key] = []types.AnchoredVar{}
	for _, v := range values {
		c.data[key] = append(c.data[key],
			types.AnchoredVar{Name: vKey, Value: v})
	}
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *Collection) Set(key string, values []string) {
	c.SetCS(key, key, values)
}

// SetIndexCS will place the value under the index
// If the index is higher than the current size of the collection
// it will be appended
// with case sensitive vKey
func (c *Collection) SetIndexCS(key string, index int, vKey string, value string) {
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
// If the index is higher than the current size of the collection
// it will be appended
func (c *Collection) SetIndex(key string, index int, value string) {
	c.SetIndexCS(key, index, key, value)
}

// Remove deletes the key from the collection
func (c *Collection) Remove(key string) {
	delete(c.data, key)
}

// Data returns the stored data
func (c *Collection) Data() map[string][]string {
	cdata := make(map[string][]string)
	for k, vals := range c.data {
		cdata[k] = []string{}
		for _, v := range vals {
			cdata[k] = append(cdata[k], v.Value)
		}
	}
	return cdata
}

// Name returns the name for the current collection
func (c *Collection) Name() string {
	return c.name
}

// SetData replaces the data map with something else
// Useful for persistent collections
func (c *Collection) SetData(data map[string][]string) {
	cdata := make(map[string][]types.AnchoredVar)
	for k, vals := range data {
		cdata[k] = []types.AnchoredVar{}
		for _, v := range vals {
			cdata[k] = append(cdata[k], types.AnchoredVar{Name: k, Value: v})
		}
	}
	c.data = cdata
}

// Reset the current collection
func (c *Collection) Reset() {
	// we don't reset the collection if it wasn't used, for performance reasons
	if len(c.data) == 1 && len(c.data[""]) == 0 {
		return
	}
	c.data = nil
	c.data = map[string][]types.AnchoredVar{
		"": {},
	}
}

// NewCollection Creates a new collection
func NewCollection(variable variables.RuleVariable) *Collection {
	col := &Collection{
		data:     map[string][]types.AnchoredVar{},
		name:     variable.Name(),
		variable: variable,
	}
	return col
}
