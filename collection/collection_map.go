// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Map are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type Map interface {
	// Get returns a slice of strings for a key
	Get(key string) []string

	// FindRegex returns a slice of MatchData for the regex
	FindRegex(key *regexp.Regexp) []types.MatchData

	// FindString returns a slice of MatchData for the string
	FindString(key string) []types.MatchData

	// FindAll returns all the contained elements
	FindAll() []types.MatchData

	// Add a value to some key
	Add(key string, value string)

	// Set will replace the key's value with this slice
	Set(key string, values []string)

	// SetIndex will place the value under the index
	// If the index is higher than the current size of the CollectionMap
	// it will be appended
	SetIndex(key string, index int, value string)

	// Remove deletes the key from the CollectionMap
	Remove(key string)

	// Name returns the name for the current CollectionMap
	Name() string

	// Reset the current CollectionMap
	Reset()

	// Data returns all the data in the CollectionMap
	Data() map[string][]string

	keysRx(rx *regexp.Regexp) []string
	keys() []string
	size() int
	variable_() variables.RuleVariable
}

var _ Collection = &caseSensitiveMap{}
var _ Collection = &caseInsensitiveMap{}

// NewMap returns a collection of key->[]values. Keys in queries will be matched in a
// case-sensitive way.
func NewMap(variable variables.RuleVariable) Map {
	m := newCaseSensitiveMap(variable)
	return &m
}

// NewCaseInsensitiveMap returns a collection of key->[]values. Keys in queries will be matched in a
// case-insensitive way.
func NewCaseInsensitiveMap(variable variables.RuleVariable) Map {
	return &caseInsensitiveMap{
		caseSensitiveMap: newCaseSensitiveMap(variable),
		origKeys:         map[string]string{},
	}
}

func newCaseSensitiveMap(variable variables.RuleVariable) caseSensitiveMap {
	return caseSensitiveMap{
		name:     variable.Name(),
		variable: variable,
		data:     map[string][]string{},
	}
}

type caseSensitiveMap struct {
	data     map[string][]string
	name     string
	variable variables.RuleVariable
}

func (c *caseSensitiveMap) Get(key string) []string {
	return c.data[key]
}

func (c *caseSensitiveMap) FindRegex(key *regexp.Regexp) []types.MatchData {
	var result []types.MatchData
	for k, data := range c.data {
		if key.MatchString(k) {
			for _, val := range data {
				result = append(result, &corazarules.MatchData{
					VariableName_: c.name,
					Variable_:     c.variable,
					Key_:          k,
					Value_:        val,
				})
			}
		}
	}
	return result
}

func (c *caseSensitiveMap) FindString(key string) []types.MatchData {
	var result []types.MatchData
	if key == "" {
		return c.FindAll()
	}
	// if key is not empty
	if e, ok := c.data[key]; ok {
		for _, val := range e {
			result = append(result, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Key_:          key,
				Value_:        val,
			})
		}
	}
	return result
}

func (c *caseSensitiveMap) FindAll() []types.MatchData {
	var result []types.MatchData
	for k, data := range c.data {
		for _, val := range data {
			result = append(result, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Key_:          k,
				Value_:        val,
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

func (c *caseSensitiveMap) Add(key string, value string) {
	c.data[key] = append(c.data[key], value)
}

func (c *caseSensitiveMap) Set(key string, values []string) {
	c.data[key] = values
}

func (c *caseSensitiveMap) SetIndex(key string, index int, value string) {
	if c.data[key] == nil {
		c.data[key] = []string{value}
		return
	}

	if len(c.data[key]) <= index {
		c.data[key] = append(c.data[key], value)
		return
	}

	c.data[key][index] = value
}

func (c *caseSensitiveMap) Remove(key string) {
	delete(c.data, key)
}

func (c *caseSensitiveMap) Name() string {
	return c.name
}

func (c *caseSensitiveMap) Reset() {
	for k := range c.data {
		delete(c.data, k)
	}
}

func (c *caseSensitiveMap) Data() map[string][]string {
	return c.data
}

func (c *caseSensitiveMap) size() int {
	sz := 0
	for _, v := range c.data {
		for _, vv := range v {
			sz = len(vv)
		}
	}
	return sz
}

func (c *caseSensitiveMap) variable_() variables.RuleVariable {
	return c.variable
}

type caseInsensitiveMap struct {
	caseSensitiveMap
	origKeys map[string]string
}

func (c *caseInsensitiveMap) Get(key string) []string {
	return c.caseSensitiveMap.Get(strings.ToLower(key))
}

func (c *caseInsensitiveMap) FindRegex(key *regexp.Regexp) []types.MatchData {
	// TODO(anuraaga): Behavior is same for key-sensitive/insensitive map but should it?
	return c.caseSensitiveMap.FindRegex(key)
}

func (c *caseInsensitiveMap) FindString(key string) []types.MatchData {
	return c.remapMatches(c.caseSensitiveMap.FindString(strings.ToLower(key)))
}

func (c *caseInsensitiveMap) FindAll() []types.MatchData {
	return c.remapMatches(c.caseSensitiveMap.FindAll())
}

func (c *caseInsensitiveMap) remapMatches(matches []types.MatchData) []types.MatchData {
	for _, m := range matches {
		m.(*corazarules.MatchData).Key_ = c.origKeys[m.Key()]
	}
	return matches
}

func (c *caseInsensitiveMap) Add(key string, value string) {
	keyL := strings.ToLower(key)
	c.origKeys[keyL] = key
	c.caseSensitiveMap.Add(keyL, value)
}

func (c *caseInsensitiveMap) Set(key string, values []string) {
	keyL := strings.ToLower(key)
	c.origKeys[keyL] = key
	c.caseSensitiveMap.Set(keyL, values)
}

func (c *caseInsensitiveMap) SetIndex(key string, index int, value string) {
	keyL := strings.ToLower(key)
	c.origKeys[keyL] = key
	c.caseSensitiveMap.SetIndex(keyL, index, value)
}

func (c *caseInsensitiveMap) Remove(key string) {
	keyL := strings.ToLower(key)
	delete(c.origKeys, keyL)
	c.caseSensitiveMap.Remove(keyL)
}
