// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
)

var Noop collection.Collection = &noop{}

type noop struct{}

func (c *noop) Get(key string) []string {
	return []string{}
}

func (c *noop) FindRegex(key *regexp.Regexp) []types.MatchData {
	return []types.MatchData{}
}

func (c *noop) FindString(key string) []types.MatchData {
	return []types.MatchData{}
}

func (c *noop) FindAll() []types.MatchData {
	return []types.MatchData{}
}

func (c *noop) Add(key string, value string) {
	c.Set(key, []string{value})
}

func (c *noop) Set(key string, values []string) {}

func (c *noop) SetIndex(key string, index int, value string) {}

func (c *noop) Remove(key string) {}

func (c *noop) Name() string {
	return ""
}

var _ collection.Map = &noop{}
