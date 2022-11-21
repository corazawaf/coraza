// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"github.com/corazawaf/coraza/v3/types"
)

// Collection are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionMaps ARE NOT concurrent safe
type Collection interface {
	// Find returns a slice of MatchData for the query
	Find(*Query) []types.MatchData

	// Name returns the name for the current CollectionMap
	Name() string

	// Reset the current CollectionMap
	Reset()
}
