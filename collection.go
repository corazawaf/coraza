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

	"github.com/jptosso/coraza-waf/v2/types/variables"
	"github.com/jptosso/coraza-waf/v2/utils"
)

// Collections are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: Collections ARE NOT concurrent safe
type Collection struct {
	data map[string][]string
	name string

	// The key used to store the collection if it must persist
	PersistenceKey string
}

// Get returns a slice of strings for a key
func (c *Collection) Get(key string) []string {
	return c.data[key]
}

//Find is returns a slice of MatchData for the
// regex or key, exceptions are used to skip
// some keys
func (c *Collection) Find(key string, re *regexp.Regexp, exceptions []string) []MatchData {
	cdata := c.data
	//we return every value in case there is no key but there is a collection
	va, _ := variables.ParseVariable(c.name)
	if len(key) == 0 {
		data := []MatchData{}
		for k := range c.data {
			if utils.StringInSlice(k, exceptions) {
				continue
			}
			for _, v := range c.data[k] {
				data = append(data, MatchData{
					Variable:     va,
					VariableName: c.name,
					Key:          k,
					Value:        v,
				})
			}
		}
		return data
	}

	// Regex
	if re != nil {
		result := []MatchData{}
		for k := range cdata {
			if utils.StringInSlice(k, exceptions) {
				continue
			}
			if re.Match([]byte(k)) {
				for _, d := range cdata[k] {
					result = append(result, MatchData{
						VariableName: c.name,
						Variable:     va,
						Key:          k,
						Value:        d,
					})
				}
			}
		}
		return result
	} else {
		ret := []MatchData{}
		//We pass through every record to apply filters
		for k := range cdata {
			if utils.StringInSlice(k, exceptions) {
				continue
			}
			if k == key {
				for _, kd := range cdata[k] {
					ret = append(ret, MatchData{
						Variable:     va,
						VariableName: c.name,
						Key:          k,
						Value:        kd,
					})
				}
			}
		}
		return ret
	}
}

// GetFirstString returns the first string ocurrence of a key
func (c *Collection) GetFirstString(key string) string {
	a := c.data[key]
	if len(a) > 0 {
		return a[0]
	} else {
		return ""
	}
}

// GetFirstInt64 returns the first int64 ocurrence of a key
func (c *Collection) GetFirstInt64(key string) int64 {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.ParseInt(a[0], 10, 64)
		return i
	} else {
		return 0
	}
}

// GetFirstInt returns the first int ocurrence of a key
func (c *Collection) GetFirstInt(key string) int {
	a := c.data[key]
	if len(a) > 0 {
		i, _ := strconv.Atoi(a[0])
		return i
	} else {
		return 0
	}
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
	if utils.StringInSlice(value, c.data[key]) {
		return
	}
	c.Add(key, value)
}

// Set will replace the key's value with this slice
func (c *Collection) Set(key string, value []string) {
	c.data[key] = value
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
	c.data = map[string][]string{}
	c.data[""] = []string{}
}

// Creates a new collection
func NewCollection(name string) *Collection {
	col := &Collection{
		data: map[string][]string{},
		name: name,
	}
	return col
}
