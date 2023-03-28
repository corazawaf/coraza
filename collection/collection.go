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

	// Set sets the value of this Single
	Set(string)
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

// Map are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type Map interface {
	Keyed

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
}
