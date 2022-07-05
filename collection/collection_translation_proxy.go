// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collection

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// CollectionTranslationProxy are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionTranslationProxys ARE NOT concurrent safe
type CollectionTranslationProxy struct {
	data1    map[string][]types.AnchoredVar
	data2    map[string][]types.AnchoredVar
	name     string
	variable variables.RuleVariable
}

// Get returns a slice of strings for a key
func (c *CollectionTranslationProxy) Get(key string) []string {
	keys := []string{}
	for k := range c.data1 {
		keys = append(keys, k)
	}
	for k := range c.data2 {
		keys = append(keys, k)
	}
	return keys
}

// FindRegex returns a slice of MatchData for the regex
func (c *CollectionTranslationProxy) FindRegex(key *regexp.Regexp) []types.MatchData {
	return nil
}

// FindString returns a slice of MatchData for the string
func (c *CollectionTranslationProxy) FindString(key string) []types.MatchData {
	return nil
}

// GetFirstString returns the first string occurrence of a key
func (c *CollectionTranslationProxy) String() string {
	return ""
}

// GetFirstInt64 returns the first int64 occurrence of a key
func (c *CollectionTranslationProxy) Int64() int64 {
	return 0
}

// GetFirstInt returns the first int occurrence of a key
func (c *CollectionTranslationProxy) Int() int {
	return 0
}

// AddCS a value to some key with case sensitive vKey
func (c *CollectionTranslationProxy) AddCS(key string, vKey string, vVal string) {
	// Not implemented
}

// Add a value to some key
func (c *CollectionTranslationProxy) Add(key string, value string) {
	// Not implemented
}

// AddUniqueCS will add a value to a key if it is not already there
// with case sensitive vKey
func (c *CollectionTranslationProxy) AddUniqueCS(key string, vKey string, vVal string) {
	// Not implemented
}

// AddUnique will add a value to a key if it is not already there
func (c *CollectionTranslationProxy) AddUnique(key string, value string) {
	// Not implemented
}

// SetCS will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
// with case sensitive vKey
func (c *CollectionTranslationProxy) SetCS(key string, vKey string, values []string) {
	// Not implemented
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *CollectionTranslationProxy) Set(key string, values []string) {
	// Not implemented
}

// SetIndexCS will place the value under the index
// If the index is higher than the current size of the CollectionTranslationProxy
// it will be appended
// with case sensitive vKey
func (c *CollectionTranslationProxy) SetIndexCS(key string, index int, vKey string, value string) {
	// Not implemented
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the CollectionTranslationProxy
// it will be appended
func (c *CollectionTranslationProxy) SetIndex(key string, index int, value string) {
	// Not implemented
}

// Remove deletes the key from the CollectionTranslationProxy
func (c *CollectionTranslationProxy) Remove(key string) {
	// Not implemented
}

// Name returns the name for the current CollectionTranslationProxy
func (c *CollectionTranslationProxy) Name() string {
	return c.name
}

// Reset the current CollectionTranslationProxy
func (c *CollectionTranslationProxy) Reset() {
	for k := range c.data1 {
		delete(c.data1, k)
	}
	for k := range c.data2 {
		delete(c.data2, k)
	}
}

var _ Collection = &CollectionTranslationProxy{}

func NewCollectionTranslationProxy(variable variables.RuleVariable, c1 Collection, c2 Collection) Collection {
	c1Map := (c1).(*CollectionMap)
	res := &CollectionTranslationProxy{
		name:     variable.Name(),
		variable: variable,
		data1:    c1Map.data,
	}
	if c2 != nil {
		c2Map := (c2).(*CollectionMap)
		res.data2 = c2Map.data
	}
	return res
}
