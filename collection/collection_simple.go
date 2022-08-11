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

// Simple are used to store VARIABLE data
// for transactions, this data structured is designed
// to store slices of data for keys
// Important: CollectionSimples ARE NOT concurrent safe
type Simple struct {
	data     string
	name     string
	variable variables.RuleVariable
}

// FindRegex returns a slice of MatchData for the regex
func (c *Simple) FindRegex(key *regexp.Regexp) []types.MatchData {
	return c.FindAll()
}

// FindString returns a slice of MatchData for the string
func (c *Simple) FindString(key string) []types.MatchData {
	return c.FindAll()
}

// FindAll returns a single MatchData for the current data
func (c *Simple) FindAll() []types.MatchData {
	return []types.MatchData{
		{
			VariableName: c.name,
			Variable:     c.variable,
			Value:        c.data,
		},
	}
}

// String returns the first string occurrence of a key
func (c *Simple) String() string {
	return c.data
}

// Int64 returns the first int64 occurrence of a key
func (c *Simple) Int64() int64 {
	return int64(c.Int())
}

// Int returns the first int occurrence of a key
func (c *Simple) Int() int {
	r, _ := strconv.ParseInt(c.data, 10, 32)
	return int(r)
}

// Set will replace the key's value with this slice
// internally converts [] string to []types.AnchoredVar
func (c *Simple) Set(value string) {
	c.data = value
}

// Name returns the name for the current CollectionSimple
func (c *Simple) Name() string {
	return c.name
}

// Reset the current CollectionSimple
func (c *Simple) Reset() {
	c.data = ""
}

var _ Collection = &Simple{}

// NewSimple creates a new CollectionSimple
func NewSimple(variable variables.RuleVariable) *Simple {
	return &Simple{
		variable: variable,
		name:     variable.Name(),
	}
}
