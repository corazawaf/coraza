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
)

// Collection are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type Collection interface {
	// Get returns a slice of strings for a key
	Get(key string) []string

	// FindRegex returns a slice of MatchData for the regex
	FindRegex(key *regexp.Regexp) []types.MatchData

	// FindString returns a slice of MatchData for the string
	FindString(key string) []types.MatchData

	// String returns the string value, only usable by CollectionSimple
	String() string

	// Int returns the int value, only usable by CollectionSimple
	Int() int

	// Int64 returns the int64 value, only usable by CollectionSimple
	Int64() int64

	// AddCS a value to some key with case sensitive vKey
	AddCS(key string, vKey string, vVal string)

	// Add a value to some key
	Add(key string, value string)

	// AddUniqueCS will add a value to a key if it is not already there
	// with case sensitive vKey
	AddUniqueCS(key string, vKey string, vVal string)

	// AddUnique will add a value to a key if it is not already there
	AddUnique(key string, value string)

	// SetCS will replace the key's value with this slice
	// internally converts [] string to []types.AnchoredVar
	// with case sensitive vKey
	SetCS(key string, vKey string, values []string)

	// Set will replace the key's value with this slice
	// internally converts [] string to []types.AnchoredVar
	Set(key string, values []string)

	// SetIndexCS will place the value under the index
	// If the index is higher than the current size of the CollectionMap
	// it will be appended
	// with case sensitive vKey
	SetIndexCS(key string, index int, vKey string, value string)

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
}
