// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type Map interface {
	Get(key string) []string
	FindRegex(key *regexp.Regexp) []types.MatchData
	FindString(key string) []types.MatchData
	FindAll() []types.MatchData
	keysRx(rx *regexp.Regexp) []string
	keys() []string
	AddCS(key string, vKey string, vVal string)
	Add(key string, value string)
	AddUniqueCS(key string, vKey string, vVal string)
	AddUnique(key string, value string)
	SetCS(key string, vKey string, values []string)
	Set(key string, values []string)
	SetIndexCS(key string, index int, vKey string, value string)
	SetIndex(key string, index int, value string)
	Remove(key string)
	Name() string
	Reset()
	Data() map[string][]string

	rawData() map[string][]types.AnchoredVar
	variable_() variables.RuleVariable
}

// Map are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type caseSensitiveMap struct {
	data     map[string][]types.AnchoredVar
	name     string
	variable variables.RuleVariable
}

// Get returns a slice of strings for a key
func (c *caseSensitiveMap) Get(key string) []string {
	var values []string
	for _, a := range c.data[key] {
		values = append(values, a.Value)
	}
	return values
}

// FindRegex returns a slice of MatchData for the regex
func (c *caseSensitiveMap) FindRegex(key *regexp.Regexp) []types.MatchData {
	var result []types.MatchData
	for k, data := range c.data {
		if key.MatchString(k) {
			for _, d := range data {
				result = append(result, &corazarules.MatchData{
					VariableName_: c.name,
					Variable_:     c.variable,
					Key_:          d.Name,
					Value_:        d.Value,
				})
			}
		}
	}
	return result
}

// FindString returns a slice of MatchData for the string
func (c *caseSensitiveMap) FindString(key string) []types.MatchData {
	var result []types.MatchData
	if key == "" {
		return c.FindAll()
	}
	// if key is not empty
	if e, ok := c.data[key]; ok {
		for _, aVar := range e {
			result = append(result, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Key_:          aVar.Name,
				Value_:        aVar.Value,
			})
		}
	}
	return result
}

// FindAll returns all the contained elements
func (c *caseSensitiveMap) FindAll() []types.MatchData {
	var result []types.MatchData
	for _, data := range c.data {
		for _, d := range data {
			result = append(result, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Key_:          d.Name,
				Value_:        d.Value,
			})
		}
	}
	return result
}

func (c *caseSensitiveMap) keysRx(rx *regexp.Regexp) []string {
	var keys []string
	for k := range c.data {
		if rx.MatchString(k) {
			keys = append(keys, k)
		}
	}
	return keys
}

func (c *caseSensitiveMap) keys() []string {
	var keys []string
	for k := range c.data {
		keys = append(keys, k)
	}
	return keys
}

// AddCS a value to some key with case sensitive vKey
func (c *caseSensitiveMap) AddCS(key string, vKey string, vVal string) {
	aVal := types.AnchoredVar{Name: vKey, Value: vVal}
	c.data[key] = append(c.data[key], aVal)
}

// Add a value to some key
func (c *caseSensitiveMap) Add(key string, value string) {
	c.AddCS(key, key, value)
}

// AddUniqueCS will add a value to a key if it is not already there
// with case sensitive vKey
func (c *caseSensitiveMap) AddUniqueCS(key string, vKey string, vVal string) {
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
func (c *caseSensitiveMap) AddUnique(key string, value string) {
	c.AddUniqueCS(key, key, value)
}

// SetCS will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
// with case sensitive vKey
func (c *caseSensitiveMap) SetCS(key string, vKey string, values []string) {
	c.data[key] = make([]types.AnchoredVar, 0, len(values))
	for _, v := range values {
		c.data[key] = append(c.data[key], types.AnchoredVar{Name: vKey, Value: v})
	}
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *caseSensitiveMap) Set(key string, values []string) {
	c.SetCS(key, key, values)
}

// SetIndexCS will place the value under the index
// If the index is higher than the current size of the CollectionMap
// it will be appended
// with case sensitive vKey
func (c *caseSensitiveMap) SetIndexCS(key string, index int, vKey string, value string) {
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
func (c *caseSensitiveMap) SetIndex(key string, index int, value string) {
	c.SetIndexCS(key, index, key, value)
}

// Remove deletes the key from the CollectionMap
func (c *caseSensitiveMap) Remove(key string) {
	delete(c.data, key)
}

// Name returns the name for the current CollectionMap
func (c *caseSensitiveMap) Name() string {
	return c.name
}

// Reset the current CollectionMap
func (c *caseSensitiveMap) Reset() {
	for k := range c.data {
		delete(c.data, k)
	}
}

// Data returns all the data in the CollectionMap
func (c *caseSensitiveMap) Data() map[string][]string {
	result := map[string][]string{}
	for k, v := range c.data {
		result[k] = make([]string, 0, len(v))
		for _, a := range v {
			result[k] = append(result[k], a.Value)
		}
	}
	return result
}

func (c *caseSensitiveMap) rawData() map[string][]types.AnchoredVar {
	return c.data
}

func (c *caseSensitiveMap) variable_() variables.RuleVariable {
	return c.variable
}

var _ Collection = &caseSensitiveMap{}

// NewMap returns a collection of key->[]values
func NewMap(variable variables.RuleVariable) Map {
	return &caseSensitiveMap{
		name:     variable.Name(),
		variable: variable,
		data:     map[string][]types.AnchoredVar{},
	}
}
