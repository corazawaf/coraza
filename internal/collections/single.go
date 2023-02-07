// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type Single struct {
	data     string
	name     string
	variable variables.RuleVariable
}

var _ collection.Single = &Single{}

// NewSingle creates a new Single.
func NewSingle(variable variables.RuleVariable) *Single {
	return &Single{
		variable: variable,
		name:     variable.Name(),
	}
}

func (c *Single) FindAll() []types.MatchData {
	return []types.MatchData{
		&corazarules.MatchData{
			VariableName_: c.name,
			Variable_:     c.variable,
			Value_:        c.data,
		},
	}
}

func (c *Single) Get() string {
	return c.data
}

func (c *Single) Set(value string) {
	c.data = value
}

func (c *Single) Name() string {
	return c.name
}

func (c *Single) Reset() {
	c.data = ""
}
