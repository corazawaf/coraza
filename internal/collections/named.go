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

// NamedCollection is a Collection that also keeps track of names.
type NamedCollection struct {
	*Map
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
}

// Set will replace the key's value with this slice
func (c *NamedCollection) Set(key string, values []string) {
	c.Map.Set(key, values)
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the CollectionMap
// it will be appended
func (c *NamedCollection) SetIndex(key string, index int, value string) {
	c.Map.SetIndex(key, index, value)
}

// Remove deletes the key from the CollectionMap
func (c *NamedCollection) Remove(key string) {
	c.Map.Remove(key)
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
}

func (c *NamedCollection) Names(rv variables.RuleVariable) collection.Collection {
	return &NamedCollectionNames{
		name:       rv.Name(),
		variable:   rv,
		collection: c,
	}
}

func (c *NamedCollection) String() string {
	return fmt.Sprint(c.Map)
}

type NamedCollectionNames struct {
	name       string
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
	// Iterates over all the MatchData and adds the key element also to the Key field (The key value may be the value that is matched,
	// but it is still also the key of the pair and it is needed to print the matched var name)
	for _, k := range c.collection.Map.FindAll() {
		res = append(res, &corazarules.MatchData{
			VariableName_: c.name,
			Variable_:     c.variable,
			Key_:          k.Key(),
			Value_:        k.Key(),
		})
	}
	return res
}

func (c *NamedCollectionNames) Name() string {
	return c.name
}

func (c *NamedCollectionNames) String() string {
	res := strings.Builder{}
	res.WriteString(c.name)
	res.WriteString(": ")
	for i, k := range c.collection.Map.FindAll() {
		if i > 0 {
			res.WriteString(",")
		}
		res.WriteString(k.Key())
	}
	return res.String()
}
