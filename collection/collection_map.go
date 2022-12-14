// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Map are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type Map struct {
	data              map[string][]string
	name              string
	variable          variables.RuleVariable
	isKeySensitiveKey bool
}

// Get returns a slice of strings for a key
// Get is always case-insensitive
func (c *Map) Get(key string) []string {
	var values []string
	for k, a := range c.data {
		if strings.AsciiEqualFold(key, k) {
			values = make([]string, 0, len(a))
			for _, v := range a {
				values = append(values, v)
			}
			return values
		}
	}
	return values
}

func (c *Map) Find(query *Query) []types.MatchData {
	switch query.queryType {
	case queryTypeAll:
		return c.findAll()
	case queryTypeRegex:
		return c.findRegex(query.regex)
	case queryTypeEquals:
		return c.findString(query.exactMatch)
	}
	return nil
}

// FindRegex returns a slice of MatchData for the regex
func (c *Map) findRegex(key *regexp.Regexp) []types.MatchData {
	var result []types.MatchData
	for k, data := range c.data {
		if key.MatchString(k) {
			for _, d := range data {
				result = append(result, &corazarules.MatchData{
					VariableName_: c.name,
					Variable_:     c.variable,
					Key_:          k,
					Value_:        d,
				})
			}
		}
	}
	return result
}

// findString returns a slice of MatchData for the string
func (c *Map) findString(key string) []types.MatchData {
	var result []types.MatchData
	if key == "" {
		return c.findAll()
	}
	for cKey, aVar := range c.data {
		if (!c.isKeySensitiveKey && strings.AsciiEqualFold(cKey, key)) || (c.isKeySensitiveKey && cKey == key) {
			for _, v := range aVar {
				result = append(result, &corazarules.MatchData{
					VariableName_: c.name,
					Variable_:     c.variable,
					Key_:          key,
					Value_:        v,
				})
			}
		}
	}
	return result
}

// FindAll returns all the contained elements
func (c *Map) findAll() []types.MatchData {
	var result []types.MatchData
	for key, data := range c.data {
		for _, d := range data {
			result = append(result, &corazarules.MatchData{
				VariableName_: c.name,
				Variable_:     c.variable,
				Key_:          key,
				Value_:        d,
			})
		}
	}
	return result
}

func (c *Map) keysRx(rx *regexp.Regexp) []string {
	var keys []string
	for k := range c.data {
		if rx.MatchString(k) {
			keys = append(keys, k)
		}
	}
	return keys
}

func (c *Map) keys() []string {
	var keys []string
	for k := range c.data {
		keys = append(keys, k)
	}
	return keys
}

// Add a value to some key
func (c *Map) Add(key string, value string) {
	c.data[key] = append(c.data[key], value)
}

// AddUnique will add a value to a key if it is not already there
func (c *Map) AddUnique(key string, vVal string) {
	ckey := key
	if c.data[ckey] == nil {
		c.Add(key, vVal)
		return
	}

	for _, a := range c.data[key] {
		if a == vVal {
			return
		}
	}
	c.Add(key, vVal)
}

// Set will replace the key's value with this slice
// internally converts [] string to []anchoredVar
func (c *Map) Set(key string, values []string) {
	c.data[key] = make([]string, 0, len(values))
	ckey := key
	if !c.isKeySensitiveKey {
		ckey = strings.AsciiLower(key)
	}
	for _, v := range values {
		c.data[ckey] = append(c.data[ckey], v)
	}
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the CollectionMap
// it will be appended
func (c *Map) SetIndex(key string, index int, value string) {
	cKey := key
	if !c.isKeySensitiveKey {
		cKey = strings.AsciiLower(key)
	}
	if c.data[cKey] == nil {
		c.data[cKey] = []string{value}
		return
	}
	if len(c.data[cKey]) <= index {
		c.data[cKey] = append(c.data[cKey], value)
		return
	}
	c.data[cKey][index] = value
}

// Remove deletes the key from the CollectionMap
func (c *Map) Remove(key string) {
	delete(c.data, key)
}

// Name returns the name for the current CollectionMap
func (c *Map) Name() string {
	return c.name
}

// Reset the current CollectionMap
func (c *Map) Reset() {
	for k := range c.data {
		delete(c.data, k)
	}
}

// Data returns all the data in the CollectionMap
func (c *Map) Data() map[string][]string {
	result := map[string][]string{}
	for k, v := range c.data {
		result[k] = make([]string, 0, len(v))
		for _, a := range v {
			result[k] = append(result[k], a)
		}
	}
	return result
}

var _ Collection = &Map{}

// NewMap returns a collection of key->[]values
// If caseSensitiveKeys is false, the keys will be converted to lower case
// Some keys must be stored using lower case keys, like HTTP headers.
// Other maps like ARGS are case sensitive, "User != user"
// But a query will always return the original case sensitive key,
// regarding of isCaseSensitiveKey
func NewMap(variable variables.RuleVariable, isCaseSensitiveKey bool) *Map {
	return &Map{
		name:              variable.Name(),
		variable:          variable,
		data:              map[string][]string{},
		isKeySensitiveKey: isCaseSensitiveKey,
	}
}
