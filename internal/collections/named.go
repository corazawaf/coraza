// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// NamedCollection is a Collection that also keeps track of unique names.
type NamedCollection struct {
	*Map
	names []string
}

var _ collection.Map = &NamedCollection{}

func NewNamedCollection(rv variables.RuleVariable) *NamedCollection {
	return &NamedCollection{
		Map: NewMap(rv),
	}
}

// Add a value to some key
func (c *NamedCollection) Add(key string, value string) {
	c.Map.Add(key, value)
	c.addName(key)
}

// Set will replace the key's value with this slice
func (c *NamedCollection) Set(key string, values []string) {
	c.Map.Set(key, values)
	c.addName(key)
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the CollectionMap
// it will be appended
func (c *NamedCollection) SetIndex(key string, index int, value string) {
	c.Map.SetIndex(key, index, value)
	c.addName(key)
}

// Remove deletes the key from the CollectionMap
func (c *NamedCollection) Remove(key string) {
	c.Map.Remove(key)
	for i, n := range c.names {
		if n == key {
			c.names = append(c.names[:i], c.names[i+1:]...)
			return
		}
	}
}

// Data is an internal method used for serializing to JSON
func (c *NamedCollection) Data() map[string][]string {
	result := map[string][]string{}
	for k, v := range c.data {
		result[k] = make([]string, 0, len(v))
		for _, a := range v {
			result[k] = append(result[k], a.value)
		}
	}
	return result
}

// Name returns the name for the current CollectionMap
func (c *NamedCollection) Name() string {
	return c.Map.Name()
}

func (c *NamedCollection) Reset() {
	c.Map.Reset()
	c.names = nil
}

func (c *NamedCollection) Names(rv variables.RuleVariable) collection.Collection {
	return &NamedCollectionNames{
		variable:   rv,
		collection: c,
	}
}

func (c *NamedCollection) String() string {
	return fmt.Sprint(c.Map)
}

func (c *NamedCollection) addName(key string) {
	for _, n := range c.names {
		if n == key {
			return
		}
	}
	c.names = append(c.names, key)
}

type NamedCollectionNames struct {
	variable   variables.RuleVariable
	collection *NamedCollection
}

func (c *NamedCollectionNames) FindRegex(key *regexp.Regexp) []types.MatchData {
	panic("selection operator not supported")
}

func (c *NamedCollectionNames) FindString(key string) []types.MatchData {
	panic("selection operator not supported")
}

func (c *NamedCollectionNames) FindAll() []types.MatchData {
	var res []types.MatchData
	for _, k := range c.collection.names {
		res = append(res, &corazarules.MatchData{
			Variable_: c.variable,
			Value_:    k,
		})
	}
	return res
}

func (c *NamedCollectionNames) Name() string {
	return c.variable.Name()
}

func (c *NamedCollectionNames) Reset() {
}

func (c *NamedCollectionNames) String() string {
	res := strings.Builder{}
	res.WriteString(c.variable.Name())
	res.WriteString(": ")
	for i, k := range c.collection.names {
		if i > 0 {
			res.WriteString(",")
		}
		res.WriteString(k)
	}
	return res.String()
}
