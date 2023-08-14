// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Persistent uses collection.Map.
type Persistent struct {
	variable      variables.RuleVariable
	engine        plugintypes.PersistenceEngine
	collectionKey string
}

func NewPersistent(variable variables.RuleVariable, engine plugintypes.PersistenceEngine) *Persistent {
	return &Persistent{
		variable:      variable,
		engine:        engine,
		collectionKey: "",
	}
}

func (c *Persistent) Init(key string) {
	c.collectionKey = key
}

func (c *Persistent) Get(key string) []string {
	res, _ := c.engine.Get(c.variable.Name(), c.collectionKey, key) //nolint:errcheck
	return []string{res}
}

func (c *Persistent) FindRegex(key *regexp.Regexp) []types.MatchData {
	return nil
}

func (c *Persistent) FindString(key string) []types.MatchData {
	res, _ := c.engine.Get(c.variable.Name(), c.collectionKey, key) //nolint:errcheck
	return []types.MatchData{&corazarules.MatchData{
		Variable_: c.variable,
		Key_:      key,
		Value_:    res,
	},
	}
}

func (c *Persistent) FindAll() []types.MatchData {
	return nil
}

func (c *Persistent) SetOne(key string, value string) {
	c.engine.Set(c.variable.Name(), c.collectionKey, key, value) //nolint:errcheck
}

func (c *Persistent) Set(key string, values []string) {
	c.engine.Set(c.variable.Name(), c.collectionKey, key, values[0]) //nolint:errcheck
}

func (c *Persistent) Remove(key string) {
	c.engine.Remove(c.variable.Name(), c.collectionKey, key) //nolint:errcheck
}

func (c *Persistent) Sum(key string, sum int) {
	c.engine.Sum(c.variable.Name(), c.collectionKey, key, sum) //nolint:errcheck
}

func (c *Persistent) Name() string {
	return c.variable.Name()
}

var _ collection.Persistent = &Persistent{}
