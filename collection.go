// Copyright 2021 Juan Pablo Tosso
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

	"github.com/jptosso/coraza-waf/v2/types/variables"
	utils "github.com/jptosso/coraza-waf/v2/utils/strings"
)

// Collection are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: Collections ARE NOT concurrent safe
type Collection struct {
	data     map[string][]string
	name     string
	variable variables.RuleVariable
}

// Get returns a slice of strings for a key
func (c *Collection) Get(key string) []string {
	return c.data[strings.ToLower(key)]
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
					Key:          k,
					Value:        d,
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
		for k, data := range c.data {
			for _, d := range data {
				result = append(result, MatchData{
					VariableName: c.name,
					Variable:     c.variable,
					Key:          k,
					Value:        d,
				})
			}
		}
		return result
	}
	// if key is not empty
	if e, ok := c.data[key]; ok {
		for _, value := range e {
			result = append(result, MatchData{
				VariableName: c.name,
				Variable:     c.variable,
				Key:          key,
				Value:        value,
			})
		}
	}
	return result

}

// GetFirstString returns the first string occurrence of a key
func (c *Collection) GetFirstString(key string) string {
	if a, ok := c.data[key]; ok && len(a) > 0 {
		return a[0]
	}
	return ""
}

// GetFirstInt64 returns the first int64 occurrence of a key
func (c *Collection) GetFirstInt64(key string) int64 {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.ParseInt(a[0], 10, 64)
		return i
	}
	return 0
}

// GetFirstInt returns the first int occurrence of a key
func (c *Collection) GetFirstInt(key string) int {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.Atoi(a[0])
		return i
	}
	return 0
}

// Add a value to some key
func (c *Collection) Add(key string, value string) {
	c.data[key] = append(c.data[key], value)
}

// AddUnique will add a value to a key if it is not already there
func (c *Collection) AddUnique(key string, value string) {
	if c.data[key] == nil {
		c.Add(key, value)
		return
	}
	if utils.InSlice(value, c.data[key]) {
		return
	}
	c.Add(key, value)
}

// Set will replace the key's value with this slice
func (c *Collection) Set(key string, value []string) {
	c.data[key] = value
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the collection
// it will be appended
func (c *Collection) SetIndex(key string, index int, value string) {
	if c.data[key] == nil {
		c.data[key] = []string{}
	}
	if len(c.data[key]) <= index {
		c.data[key] = append(c.data[key], value)
		return
	}
	c.data[key][index] = value
}

// Remove deletes the key from the collection
func (c *Collection) Remove(key string) {
	delete(c.data, key)
}

// Data returns the stored data
func (c *Collection) Data() map[string][]string {
	return c.data
}

// Name returns the name for the current collection
func (c *Collection) Name() string {
	return c.name
}

// SetData replaces the data map with something else
// Useful for persistent collections
func (c *Collection) SetData(data map[string][]string) {
	c.data = data
}

// Reset the current collection
func (c *Collection) Reset() {
	c.data = nil
	c.data = map[string][]string{
		"": {},
	}
}

// NewCollection Creates a new collection
func NewCollection(variable variables.RuleVariable) *Collection {
	col := &Collection{
		data:     map[string][]string{},
		name:     variable.Name(),
		variable: variable,
	}
	return col
}
