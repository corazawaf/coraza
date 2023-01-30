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
	return &caseSensitiveMap{
		name:     variable.Name(),
		variable: variable,
		data:     map[string][]string{},
	}
}

// NewCaseInsensitiveMap returns a collection of key->[]values. Keys in queries will be matched in a
// case-insensitive way.
func NewCaseInsensitiveMap(variable variables.RuleVariable) Map {
	return &caseInsensitiveMap{
		name:     variable.Name(),
		variable: variable,
		data:     map[string][]keyVal{},
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
			sz += len(vv)
		}
	}
	return sz
}

func (c *caseSensitiveMap) variable_() variables.RuleVariable {
	return c.variable
}

type caseInsensitiveMap struct {
	data     map[string][]keyVal
	name     string
	variable variables.RuleVariable
}

func (c *caseInsensitiveMap) Data() map[string][]string {
	result := map[string][]string{}
	for k, v := range c.data {
		result[k] = make([]string, 0, len(v))
		for _, a := range v {
			result[k] = append(result[k], a.val)
		}
	}
	return result
}

func (c *caseInsensitiveMap) keysRx(rx *regexp.Regexp) []string {
	var keys []string
	for k := range c.data {
		if rx.MatchString(k) {
			keys = append(keys, k)
		}
	}
	return keys
}

func (c *caseInsensitiveMap) keys() []string {
	var keys []string
	for k := range c.data {
		keys = append(keys, k)
	}
	return keys
}

func (c *caseInsensitiveMap) size() int {
	sz := 0
	for _, v := range c.data {
		for _, vv := range v {
			sz += len(vv.val)
		}
	}
	return sz
}

func (c *caseInsensitiveMap) variable_() variables.RuleVariable {
	return c.variable
}

type keyVal struct {
	key string
	val string
}

func (c *caseInsensitiveMap) Get(key string) []string {
	keyL := strings.ToLower(key)
	var values []string
	for _, a := range c.data[keyL] {
		values = append(values, a.val)
	}
	return values
}

func (c *caseInsensitiveMap) FindRegex(key *regexp.Regexp) []types.MatchData {
	var result []types.MatchData
	for k, data := range c.data {
		if key.MatchString(k) {
			for _, d := range data {
				result = append(result, &corazarules.MatchData{
					VariableName_: c.name,
					Variable_:     c.variable,
					Key_:          d.key,
					Value_:        d.val,
				})
			}
		}
	}
	return result
}

func (c *caseInsensitiveMap) FindString(key string) []types.MatchData {
	keyL := strings.ToLower(key)
	var result []types.MatchData
	if key == "" {
		return c.FindAll()
	}
	// if key is not empty
	if e, ok := c.data[keyL]; ok {
		for _, aVar := range e {
			result = append(result, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Key_:          aVar.key,
				Value_:        aVar.val,
			})
		}
	}
	return result
}

func (c *caseInsensitiveMap) FindAll() []types.MatchData {
	var result []types.MatchData
	for _, data := range c.data {
		for _, d := range data {
			result = append(result, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Key_:          d.key,
				Value_:        d.val,
			})
		}
	}
	return result
}

func (c *caseInsensitiveMap) Add(key string, value string) {
	keyL := strings.ToLower(key)
	c.data[keyL] = append(c.data[keyL], keyVal{key, value})
}

func (c *caseInsensitiveMap) Set(key string, values []string) {
	var kv []keyVal
	for _, v := range values {
		kv = append(kv, keyVal{key, v})
	}
	keyL := strings.ToLower(key)
	c.data[keyL] = kv
}

func (c *caseInsensitiveMap) SetIndex(key string, index int, value string) {
	keyL := strings.ToLower(key)
	d := c.data[keyL]
	switch {
	case d == nil:
		c.Set(key, []string{value})
	case len(d) <= index:
		c.Add(key, value)
	default:
		d[index].key = key
		d[index].val = value
	}
}

func (c *caseInsensitiveMap) Remove(key string) {
	keyL := strings.ToLower(key)
	delete(c.data, keyL)
}

func (c *caseInsensitiveMap) Name() string {
	return c.name
}

func (c *caseInsensitiveMap) Reset() {
	for k := range c.data {
		delete(c.data, k)
	}
}
