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
//
// Keys are kept in the order they were first added, and every read returns
// them in that order, the values of each key in the order they were added.
// Rules see a collection's values in the order the request carried them, as
// in ModSecurity, so the last match a chained rule reads through TX:0-9 or
// MATCHED_VAR is the same on every evaluation of the same request. Ranging
// over a Go map instead gave a different order on every evaluation (#1815).
type Map struct {
	isCaseSensitive bool
	// index maps a key, lowercased unless the map is case sensitive, to its
	// position in entries.
	index map[string]int
	// entries holds one slot per key, in first-insertion order.
	entries  []mapEntry
	variable variables.RuleVariable
	// totalValues tracks TotalValues incrementally so it stays O(1) to read;
	// summing len(values) across every key on each call made checkArgumentLimit
	// (called once per Add) quadratic in the number of distinct keys.
	totalValues int
}

// mapEntry is the slot of one key in a Map.
type mapEntry struct {
	// key is the lookup key, lowercased unless the map is case sensitive.
	key    string
	values []keyValue
}

var _ collection.Map = &Map{}

// NewMap creates a new Map. By default, the Map key is case insensitive.
func NewMap(variable variables.RuleVariable) *Map {
	return &Map{
		isCaseSensitive: false,
		variable:        variable,
		index:           map[string]int{},
	}
}

// NewCaseSensitiveKeyMap creates a new Map with case sensitive keys.
func NewCaseSensitiveKeyMap(variable variables.RuleVariable) *Map {
	return &Map{
		isCaseSensitive: true,
		variable:        variable,
		index:           map[string]int{},
	}
}

// lookup returns the values stored under key, which must already be
// normalised.
func (c *Map) lookup(key string) []keyValue {
	if i, ok := c.index[key]; ok {
		return c.entries[i].values
	}
	return nil
}

// put stores values under key, which must already be normalised, appending
// a new slot when the key is not present yet.
func (c *Map) put(key string, values []keyValue) {
	if i, ok := c.index[key]; ok {
		c.entries[i].values = values
		return
	}
	c.index[key] = len(c.entries)
	c.entries = append(c.entries, mapEntry{key: key, values: values})
}

func (c *Map) Get(key string) []string {
	if len(c.entries) == 0 {
		return nil
	}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	values := c.lookup(key)
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
	for _, e := range c.entries {
		if key.MatchString(e.key) {
			n += len(e.values)
			matched = append(matched, e.values)
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
	if len(c.entries) == 0 {
		return nil
	}
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	e := c.lookup(key)
	if len(e) == 0 {
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
	for _, e := range c.entries {
		n += len(e.values)
	}
	if n == 0 {
		return nil
	}
	buf := make([]corazarules.MatchData, n)
	result := make([]types.MatchData, n)
	i := 0
	for _, e := range c.entries {
		for _, d := range e.values {
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
	if i, ok := c.index[key]; ok {
		c.entries[i].values = append(c.entries[i].values, aVal)
	} else {
		c.put(key, []keyValue{aVal})
	}
	c.totalValues++
}

// Sets the value of a key with the array of strings passed. If the key already exists, it will be overwritten.
func (c *Map) Set(key string, values []string) {
	originalKey := key
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	dataSlice := c.lookup(key)
	oldLen := len(dataSlice)
	if dataSlice == nil || cap(dataSlice) < len(values) {
		dataSlice = make([]keyValue, len(values))
	} else {
		dataSlice = dataSlice[:len(values)] // Reuse existing slice with the same length
	}
	for i, v := range values {
		dataSlice[i] = keyValue{key: originalKey, value: v}
	}
	c.put(key, dataSlice)
	c.totalValues += len(values) - oldLen
}

// SetIndex sets the value of a key at the specified index. If the key already exists, it will be overwritten.
func (c *Map) SetIndex(key string, index int, value string) {
	originalKey := key
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	values := c.lookup(key)
	av := keyValue{key: originalKey, value: value}

	switch {
	case len(values) == 0:
		c.put(key, []keyValue{av})
		c.totalValues++
	case len(values) <= index:
		c.put(key, append(values, av))
		c.totalValues++
	default:
		values[index] = av
	}
}

// Remove removes a key/value from the map.
func (c *Map) Remove(key string) {
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	i, ok := c.index[key]
	if !ok {
		return
	}
	c.totalValues -= len(c.entries[i].values)
	delete(c.index, key)
	// Shift the later slots down to keep the order; removal only comes from
	// setvar:!col.key, which is rare compared to reads.
	copy(c.entries[i:], c.entries[i+1:])
	c.entries[len(c.entries)-1] = mapEntry{}
	c.entries = c.entries[:len(c.entries)-1]
	for j := i; j < len(c.entries); j++ {
		c.index[c.entries[j].key] = j
	}
}

// Name returns the name of the map/collection.
func (c *Map) Name() string {
	return c.variable.Name()
}

// Reset removes all key/value pairs from the map.
func (c *Map) Reset() {
	clear(c.index)
	// Zero the slots so a pooled transaction does not keep the previous
	// request's values alive through the backing array.
	clear(c.entries)
	c.entries = c.entries[:0]
	c.totalValues = 0
}

// Format updates the passed strings.Builder with the formatted map key/values.
func (c *Map) Format(res *strings.Builder) {
	res.WriteString(c.variable.Name())
	res.WriteString(":\n")
	for _, e := range c.entries {
		res.WriteString("    ")
		res.WriteString(e.key)
		res.WriteString(": ")
		for i, vv := range e.values {
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
	return len(c.entries)
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
