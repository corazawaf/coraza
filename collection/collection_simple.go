// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collection

import (
	"strconv"

	"github.com/corazawaf/coraza/v3/internal/corazarules"
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

func (c *Simple) Find(_ *Query) []types.MatchData {
	return []types.MatchData{
		&corazarules.MatchData{
			VariableName_: c.name,
			Variable_:     c.variable,
			Value_:        c.data,
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
