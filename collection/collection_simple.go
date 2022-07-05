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
	"strconv"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// CollectionSimple are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionSimples ARE NOT concurrent safe
type CollectionSimple struct {
	data     string
	name     string
	variable variables.RuleVariable
}

// Get returns a slice of strings for a key
func (c *CollectionSimple) Get(key string) []string {
	// Not implemented
	return nil
}

// FindRegex returns a slice of MatchData for the regex
func (c *CollectionSimple) FindRegex(key *regexp.Regexp) []types.MatchData {
	// Not implemented
	return nil
}

// FindString returns a slice of MatchData for the string
func (c *CollectionSimple) FindString(key string) []types.MatchData {
	// Not implemented
	return nil
}

// GetFirstString returns the first string occurrence of a key
func (c *CollectionSimple) String() string {
	return c.data
}

// GetFirstInt64 returns the first int64 occurrence of a key
func (c *CollectionSimple) Int64() int64 {
	r, _ := strconv.ParseInt(c.data, 10, 64)
	return r
}

// GetFirstInt returns the first int occurrence of a key
func (c *CollectionSimple) Int() int {
	return int(c.Int64())
}

// AddCS a value to some key with case sensitive vKey
func (c *CollectionSimple) AddCS(key string, vKey string, vVal string) {
	// we don't add the value if it was already there
}

// Add a value to some key
func (c *CollectionSimple) Add(key string, value string) {
	// we don't add the value if it was already there
}

// AddUniqueCS will add a value to a key if it is not already there
// with case sensitive vKey
func (c *CollectionSimple) AddUniqueCS(key string, vKey string, vVal string) {
	// we don't add the value if it was already there
}

// AddUnique will add a value to a key if it is not already there
func (c *CollectionSimple) AddUnique(key string, value string) {
	// we don't add the value if it was already there
}

// SetCS will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
// with case sensitive vKey
func (c *CollectionSimple) SetCS(key string, vKey string, values []string) {
	// we don't add the value if it was already there
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *CollectionSimple) Set(key string, values []string) {
	if len(values) > 0 {
		c.data = values[0]
	}
}

// SetIndexCS will place the value under the index
// If the index is higher than the current size of the CollectionSimple
// it will be appended
// with case sensitive vKey
func (c *CollectionSimple) SetIndexCS(key string, index int, vKey string, value string) {
	// we don't add the value if it was already there
}

// SetIndex will place the value under the index
// If the index is higher than the current size of the CollectionSimple
// it will be appended
func (c *CollectionSimple) SetIndex(key string, index int, value string) {
	// we don't add the value if it was already there
}

// Remove deletes the key from the CollectionSimple
func (c *CollectionSimple) Remove(key string) {
	// we don't remove the key if it wasn't used, for performance reasons
}

// Name returns the name for the current CollectionSimple
func (c *CollectionSimple) Name() string {
	return c.name
}

// Reset the current CollectionSimple
func (c *CollectionSimple) Reset() {
	c.data = ""
}

var _ Collection = &CollectionSimple{}

func NewCollectionSimple(variable variables.RuleVariable) Collection {
	return &CollectionSimple{
		variable: variable,
		name:     variable.Name(),
	}
}
