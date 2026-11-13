// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type Single struct {
	data     string
	variable variables.RuleVariable
	// match is the element FindAll hands out; rewritten on every call so the
	// hundreds of rules reading REQUEST_URI & co. do not each allocate one.
	match corazarules.VariableMatch
}

var _ collection.Single = &Single{}

// NewSingle creates a new Single.
func NewSingle(variable variables.RuleVariable) *Single {
	return &Single{
		variable: variable,
	}
}

// FindAll returns the value as a one-element slice. The element is owned by the
// Single and rewritten by the next FindAll: callers must not retain it.
func (c *Single) FindAll() []types.MatchData {
	c.match = corazarules.VariableMatch{Variable_: c.variable, Value_: c.data}
	return []types.MatchData{&c.match}
}

func (c *Single) Get() string {
	return c.data
}

func (c *Single) Set(value string) {
	c.data = value
}

func (c *Single) Name() string {
	return c.variable.Name()
}

func (c *Single) Reset() {
	c.data = ""
}

func (c *Single) Format(res *strings.Builder) {
	res.WriteString(c.variable.Name())
	res.WriteString(": ")
	res.WriteString(c.data)
}

func (c *Single) String() string {
	return fmt.Sprintf("%s: %s", c.variable.Name(), c.data)
}
