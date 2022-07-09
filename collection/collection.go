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
