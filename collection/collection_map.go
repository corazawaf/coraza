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
}

// Map are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type defaultMap struct {
	data     map[string][]types.AnchoredVar
	name     string
	variable variables.RuleVariable
}

// Get returns a slice of strings for a key
func (c *defaultMap) Get(key string) []string {
	if len(c.data) == 0 {
		return nil
	}
	keyL := strings.ToLower(key)
	var values []string
	for _, a := range c.data[keyL] {
		values = append(values, a.Value)
	}
	return values
}

// FindRegex returns a slice of MatchData for the regex
func (c *defaultMap) FindRegex(key *regexp.Regexp) []types.MatchData {
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
func (c *defaultMap) FindString(key string) []types.MatchData {
	var result []types.MatchData
	if key == "" {
		return c.FindAll()
	}
	if len(c.data) == 0 {
		return nil
	}
	keyL := strings.ToLower(key)
	// if key is not empty
	if e, ok := c.data[keyL]; ok {
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
func (c *defaultMap) FindAll() []types.MatchData {
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

// Add a value to some key
func (c *defaultMap) Add(key string, value string) {
	keyL := strings.ToLower(key)
	aVal := types.AnchoredVar{Name: key, Value: value}
	c.data[keyL] = append(c.data[keyL], aVal)
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *defaultMap) Set(key string, values []string) {
	keyL := strings.ToLower(key)
	c.data[keyL] = make([]types.AnchoredVar, 0, len(values))
	for _, v := range values {
		c.data[keyL] = append(c.data[keyL], types.AnchoredVar{Name: key, Value: v})
	}
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the CollectionMap
// it will be appended
func (c *defaultMap) SetIndex(key string, index int, value string) {
	keyL := strings.ToLower(key)
	values := c.data[keyL]
	av := types.AnchoredVar{Name: key, Value: value}

	switch {
	case len(values) == 0:
		c.data[keyL] = []types.AnchoredVar{av}
	case len(values) <= index:
		c.data[keyL] = append(c.data[keyL], av)
	default:
		c.data[keyL][index] = av
	}
}

// Remove deletes the key from the CollectionMap
func (c *defaultMap) Remove(key string) {
	if len(c.data) == 0 {
		return
	}
	keyL := strings.ToLower(key)
	delete(c.data, keyL)
}

// Name returns the name for the current CollectionMap
func (c *defaultMap) Name() string {
	return c.name
}

// Reset the current CollectionMap
func (c *defaultMap) Reset() {
	for k := range c.data {
		delete(c.data, k)
	}
}

// Data returns all the data in the CollectionMap
func (c *defaultMap) Data() map[string][]string {
	result := map[string][]string{}
	for k, v := range c.data {
		result[k] = make([]string, 0, len(v))
		for _, a := range v {
			result[k] = append(result[k], a.Value)
		}
	}
	return result
}

var _ Collection = &defaultMap{}

// NewMap returns a collection of key->[]values
func NewMap(variable variables.RuleVariable) Map {
	return &defaultMap{
		name:     variable.Name(),
		variable: variable,
		data:     map[string][]types.AnchoredVar{},
	}
}
