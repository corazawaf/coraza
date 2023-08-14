// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// Persistent uses collection.Map.
type Persistent struct {
	variable variables.RuleVariable
}

var _ collection.Map = &Map{}

func NewPersistent(variable variables.RuleVariable, key string) *Map {
	return &Map{
		variable: variable,
		data:     map[string][]keyValue{},
	}
}

func (c *Persistent) Get(key string) []string {
	return nil
}

func (c *Persistent) FindRegex(key *regexp.Regexp) []types.MatchData {
	return nil
}

func (c *Persistent) FindString(key string) []types.MatchData {
	return nil
}

func (c *Persistent) FindAll() []types.MatchData {
	return nil
}

func (c *Persistent) Add(key string, value string) {

}

func (c *Persistent) Set(key string, values []string) {

}

func (c *Persistent) SetIndex(key string, index int, value string) {

}

func (c *Persistent) Remove(key string) {

}

func (c *Persistent) Name() string {
	return c.variable.Name()
}

func (c *Persistent) Reset() {

}

func (c *Persistent) Format(res *strings.Builder) {

}

func (c *Persistent) String() string {
	return ""
}

func (c *Persistent) Len() int {
	return 0
}
