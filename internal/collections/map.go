// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Map is a default collection.Map.
type Map struct {
	isCaseSensitive bool
	data            map[string][]keyValue
	variable        variables.RuleVariable
	// totalValues tracks TotalValues incrementally so it stays O(1) to read;
	// summing len(values) across every key on each call made checkArgumentLimit
	// (called once per Add) quadratic in the number of distinct keys.
	totalValues int
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
	values := c.data[key]
	if len(values) == 0 {
		return nil
	}
	result := make([]string, len(values))
	for i, v := range values {
		result[i] = v.value
	}
	return result
}

// FindRegex returns all map elements whose key matches the regular expression.
func (c *Map) FindRegex(key *regexp.Regexp) []types.MatchData {
	n := 0
	// Collect matching data slices in a single pass to avoid evaluating the regex twice per key.
	var matched [][]keyValue
	for k, data := range c.data {
		if key.MatchString(k) {
			n += len(data)
			matched = append(matched, data)
		}
	}
	if n == 0 {
		return nil
	}
	buf := make([]corazarules.MatchData, n)
	result := make([]types.MatchData, n)
	i := 0
	for _, data := range matched {
		for _, d := range data {
			buf[i] = corazarules.MatchData{
				Variable_: c.variable,
				Key_:      d.key,
				Value_:    d.value,
			}
			result[i] = &buf[i]
			i++
		}
	}
	return result
}

// FindString returns all map elements whose key matches the string.
func (c *Map) FindString(key string) []types.MatchData {
	if key == "" {
		return c.FindAll()
	}
	if len(c.data) == 0 {
		return nil
	}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	e, ok := c.data[key]
	if !ok || len(e) == 0 {
		return nil
	}
	buf := make([]corazarules.MatchData, len(e))
	result := make([]types.MatchData, len(e))
	for i, aVar := range e {
		buf[i] = corazarules.MatchData{
			Variable_: c.variable,
			Key_:      aVar.key,
			Value_:    aVar.value,
		}
		result[i] = &buf[i]
	}
	return result
}

// FindAll returns all map elements.
func (c *Map) FindAll() []types.MatchData {
	n := 0
	for _, data := range c.data {
		n += len(data)
	}
	if n == 0 {
		return nil
	}
	buf := make([]corazarules.MatchData, n)
	result := make([]types.MatchData, n)
	i := 0
	for _, data := range c.data {
		for _, d := range data {
			buf[i] = corazarules.MatchData{
				Variable_: c.variable,
				Key_:      d.key,
				Value_:    d.value,
			}
			result[i] = &buf[i]
			i++
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
	c.totalValues++
}

// Sets the value of a key with the array of strings passed. If the key already exists, it will be overwritten.
func (c *Map) Set(key string, values []string) {
	originalKey := key
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	dataSlice, exists := c.data[key]
	oldLen := len(dataSlice)
	if !exists || cap(dataSlice) < len(values) {
		dataSlice = make([]keyValue, len(values))
	} else {
		dataSlice = dataSlice[:len(values)] // Reuse existing slice with the same length
	}
	for i, v := range values {
		dataSlice[i] = keyValue{key: originalKey, value: v}
	}
	c.data[key] = dataSlice
	c.totalValues += len(values) - oldLen
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
		c.totalValues++
	case len(values) <= index:
		c.data[key] = append(c.data[key], av)
		c.totalValues++
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
	c.totalValues -= len(c.data[key])
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
	c.totalValues = 0
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

// Len returns the number of distinct keys in the map. A key holding several
// values (via repeated Add calls) is counted once -- use TotalValues to count
// every individual value instead.
func (c *Map) Len() int {
	return len(c.data)
}

// TotalValues returns the total number of individual values across every key
// in the map, unlike Len which only counts distinct keys. O(1): the count is
// maintained incrementally by Add/Set/SetIndex/Remove/Reset rather than
// recomputed here, since checkArgumentLimit calls this once per value added
// and a per-call walk over every distinct key made that quadratic.
func (c *Map) TotalValues() int {
	return c.totalValues
}

// keyValue stores the case preserved original key and value
// of the variable
type keyValue struct {
	key   string
	value string
}
