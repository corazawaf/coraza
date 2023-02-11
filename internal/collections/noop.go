// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
)

type Noop struct{}

var _ collection.Noop = &Noop{}

// NewNoop creates a new Noop.
func NewNoop() *Noop {
	return &Noop{}
}

func (c *Noop) FindAll() []types.MatchData {
	return []types.MatchData{}
}

func (c *Noop) Name() string {
	return ""
}

func (c *Noop) Reset() {}
