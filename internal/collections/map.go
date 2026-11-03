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
// Every read returns the keys in the order each was first added, and the
// values of a key in the order they were added. A repeated key is grouped
// under its first occurrence: ?a=1&b=2&a=3 reads a=1, a=3, b=2, where
// ModSecurity v2 keeps a=1, b=2, a=3. What matters is that the order is the
// same on every evaluation of the same request, so the last match a chained
// rule reads through TX:0-9 or MATCHED_VAR does not change from one
// transaction to the next. Ranging over a Go map gave a different order on
// every evaluation (#1815).
type Map struct {
	isCaseSensitive bool
	// index maps a key, lowercased unless the map is case sensitive, to its
	// position in entries.
	index map[string]int
	// entries holds one slot per key, in first-insertion order. Remove
	// leaves a deleted slot behind, reclaimed by compact.
	entries []mapEntry
	// deleted counts the deleted slots in entries.
	deleted  int
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
	// deleted marks a slot whose key was removed.
	deleted bool
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

// store sets the values of the slot at i, or appends a slot for key, which
// must already be normalised, when ok is false.
func (c *Map) store(i int, ok bool, key string, values []keyValue) {
	if ok {
		c.entries[i].values = values
		return
	}
	if c.entries == nil {
		// Start with room for a few keys: most collections hold only a
		// handful, and growing from zero would allocate at 1, 2 and 4.
		c.entries = make([]mapEntry, 0, 4)
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
		if !e.deleted && key.MatchString(e.key) {
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
		c.store(0, false, key, []keyValue{aVal})
	}
	c.totalValues++
}

// Sets the value of a key with the array of strings passed. If the key already exists, it will be overwritten.
func (c *Map) Set(key string, values []string) {
	originalKey := key
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	slot, ok := c.index[key]
	var dataSlice []keyValue
	if ok {
		dataSlice = c.entries[slot].values
	}
	oldLen := len(dataSlice)
	if !ok || cap(dataSlice) < len(values) {
		dataSlice = make([]keyValue, len(values))
	} else {
		dataSlice = dataSlice[:len(values)] // Reuse existing slice with the same length
	}
	for i, v := range values {
		dataSlice[i] = keyValue{key: originalKey, value: v}
	}
	c.store(slot, ok, key, dataSlice)
	c.totalValues += len(values) - oldLen
}

// SetIndex sets the value of a key at the specified index. If the key already exists, it will be overwritten.
func (c *Map) SetIndex(key string, index int, value string) {
	originalKey := key
	if !c.isCaseSensitive {
		key = strings.ToLower(key)
	}
	slot, ok := c.index[key]
	var values []keyValue
	if ok {
		values = c.entries[slot].values
	}
	av := keyValue{key: originalKey, value: value}

	switch {
	case len(values) == 0:
		c.store(slot, ok, key, []keyValue{av})
		c.totalValues++
	case len(values) <= index:
		c.store(slot, ok, key, append(values, av))
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
	// Mark the slot instead of shifting the later ones down, so removing
	// many keys (setvar:!tx.%{MATCHED_VAR_NAME} over every argument) stays
	// linear overall.
	c.entries[i] = mapEntry{deleted: true}
	c.deleted++
	if c.deleted > len(c.entries)/2 {
		c.compact()
	}
}

// compact drops the deleted slots, keeping the order of the others.
func (c *Map) compact() {
	n := 0
	for _, e := range c.entries {
		if e.deleted {
			continue
		}
		c.entries[n] = e
		c.index[e.key] = n
		n++
	}
	clear(c.entries[n:])
	c.entries = c.entries[:n]
	c.deleted = 0
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
	c.deleted = 0
	c.totalValues = 0
}

// Format updates the passed strings.Builder with the formatted map key/values.
func (c *Map) Format(res *strings.Builder) {
	res.WriteString(c.variable.Name())
	res.WriteString(":\n")
	for _, e := range c.entries {
		if e.deleted {
			continue
		}
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
	return len(c.index)
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
