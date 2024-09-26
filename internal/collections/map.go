// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"

	"github.com/redwanghb/coraza/v3/collection"
	"github.com/redwanghb/coraza/v3/internal/corazarules"
	"github.com/redwanghb/coraza/v3/types"
	"github.com/redwanghb/coraza/v3/types/variables"
)

// Map is a default collection.Map.
type Map struct {
	isCaseSensitive bool
	data            map[string][]keyValue
	variable        variables.RuleVariable
}

var _ collection.Map = &Map{}

// NewMap creates a new Map. By default, the Map key is case insensitive.
func NewMap(variable variables.RuleVariable) *Map {
	return &Map{
		isCaseSensitive: false,
		variable:        variable,
		data:            map[string][]keyValue{},
	}
}

// NewCaseSensitiveKeyMap creates a new Map with case sensitive keys.
func NewCaseSensitiveKeyMap(variable variables.RuleVariable) *Map {
	return &Map{
		isCaseSensitive: true,
		variable:        variable,
		data:            map[string][]keyValue{},
	}
}

func (c *Map) Get(key string) []string {
	if len(c.data) == 0 {
		return nil
	}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	var values []string
	for _, a := range c.data[key] {
		values = append(values, a.value)
	}
	return values
}

// FindRegex returns all map elements whose key matches the regular expression.
func (c *Map) FindRegex(key *regexp.Regexp) []types.MatchData {
	var result []types.MatchData
	for k, data := range c.data {
		if key.MatchString(k) {
			for _, d := range data {
				result = append(result, &corazarules.MatchData{
					Variable_: c.variable,
					Key_:      d.key,
					Value_:    d.value,
				})
			}
		}
	}
	return result
}

// FindString returns all map elements whose key matches the string.
func (c *Map) FindString(key string) []types.MatchData {
	var result []types.MatchData
	if key == "" {
		return c.FindAll()
	}
	if len(c.data) == 0 {
		return nil
	}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	// if key is not empty
	if e, ok := c.data[key]; ok {
		for _, aVar := range e {
			result = append(result, &corazarules.MatchData{
				Variable_: c.variable,
				Key_:      aVar.key,
				Value_:    aVar.value,
			})
		}
	}
	return result
}

// FindAll returns all map elements.
func (c *Map) FindAll() []types.MatchData {
	var result []types.MatchData
	for _, data := range c.data {
		for _, d := range data {
			result = append(result, &corazarules.MatchData{
				Variable_: c.variable,
				Key_:      d.key,
				Value_:    d.value,
			})
		}
	}
	return result
}

// Add adds a new key-value pair to the map.
func (c *Map) Add(key string, value string) {
	aVal := keyValue{key: key, value: value}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	c.data[key] = append(c.data[key], aVal)
}

// Set sets the value of a key with the array of strings passed. If the key already exists, it will be overwritten.
func (c *Map) Set(key string, values []string) {
	originalKey := key
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	c.data[key] = make([]keyValue, 0, len(values))
	for _, v := range values {
		c.data[key] = append(c.data[key], keyValue{key: originalKey, value: v})
	}
}

// SetIndex sets the value of a key at the specified index. If the key already exists, it will be overwritten.
func (c *Map) SetIndex(key string, index int, value string) {
	originalKey := key
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	values := c.data[key]
	av := keyValue{key: originalKey, value: value}

	switch {
	case len(values) == 0:
		c.data[key] = []keyValue{av}
	case len(values) <= index:
		c.data[key] = append(c.data[key], av)
	default:
		c.data[key][index] = av
	}
}

// Remove removes a key/value from the map.
func (c *Map) Remove(key string) {
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	if len(c.data) == 0 {
		return
	}
	delete(c.data, key)
}

// Name returns the name of the map/collection.
func (c *Map) Name() string {
	return c.variable.Name()
}

// Reset removes all key/value pairs from the map.
func (c *Map) Reset() {
	for k := range c.data {
		delete(c.data, k)
	}
}

// Format updates the passed strings.Builder with the formatted map key/values.
func (c *Map) Format(res *strings.Builder) {
	res.WriteString(c.variable.Name())
	res.WriteString(":\n")
	for k, v := range c.data {
		res.WriteString("    ")
		res.WriteString(k)
		res.WriteString(": ")
		for i, vv := range v {
			if i > 0 {
				res.WriteString(",")
			}
			res.WriteString(vv.value)
		}
		res.WriteByte('\n')
	}
}

// String returns a string representation of the map key/values.
func (c *Map) String() string {
	res := strings.Builder{}
	c.Format(&res)
	return res.String()
}

// Len returns the number of key/value pairs in the map.
func (c *Map) Len() int {
	return len(c.data)
}

// keyValue stores the case preserved original key and value
// of the variable
type keyValue struct {
	key   string
	value string
}
