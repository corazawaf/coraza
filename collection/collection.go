// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

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
	// FindAll returns matches for all the items in this Collection.
	FindAll() []types.MatchData

	// Name returns the name for the current CollectionMap
	Name() string
}

// Single is a Collection with a single element.
type Single interface {
	Collection

	// Get returns the value of this Single
	Get() string
}

// Keyed is a Collection with elements that can be selected by key.
type Keyed interface {
	Collection

	// Get returns a slice of strings for a key
	Get(key string) []string

	// FindRegex returns a slice of MatchData for the regex
	FindRegex(key *regexp.Regexp) []types.MatchData

	// FindString returns a slice of MatchData for the string
	FindString(key string) []types.MatchData
}

type Editable interface {
	Keyed

	// Remove deletes the key from the CollectionMap
	Remove(key string)

	// Set will replace the key's value with this slice
	Set(key string, values []string)

	// TODO: in v4 this should contain setters for Map and Persistence
}

// Map are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type Map interface {
	Editable

	// Add a value to some key
	Add(key string, value string)

	// SetIndex will place the value under the index
	// If the index is higher than the current size of the CollectionMap
	// it will be appended
	SetIndex(key string, index int, value string)
}

// Persistent collections won't use arrays as values
// They are designed for collections that will be stored
type Persistent interface {
	Editable

	// Initializes the input as the collection key
	Init(key string)

	// Sum will add the value to the key
	Sum(key string, sum int)

	// SetOne will replace the key's value with this string
	SetOne(key string, value string)
}
