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
	// FindRegex returns a slice of MatchData for the regex
	FindRegex(key *regexp.Regexp) []types.MatchData

	// FindString returns a slice of MatchData for the string
	FindString(key string) []types.MatchData

	// FindString returns a slice of MatchData for the string
	FindAll() []types.MatchData

	// Name returns the name for the current CollectionMap
	Name() string

	// Reset the current CollectionMap
	Reset()
}
