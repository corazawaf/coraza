// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build tinygo
// +build tinygo

package collections

import (
	"regexp"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// XML is a default collection.XML.
type XML struct {
	variable variables.RuleVariable
}

var _ collection.Map = &XML{}

func NewXML(variable variables.RuleVariable) *XML {
	return &XML{
		variable: variable,
	}
}

func (c *XML) Get(key string) []string {
	return nil
}

func (c *XML) FindRegex(key *regexp.Regexp) []types.MatchData {
	return nil
}

func (c *XML) FindString(key string) []types.MatchData {
	return nil
}

func (c *XML) FindAll() []types.MatchData {
	return nil
}

func (c *XML) Add(key string, value string) {
	// NOT IMPLEMENTED
}

func (c *XML) Set(key string, values []string) {
	// NOT IMPLEMENTED
}

func (c *XML) SetIndex(key string, index int, value string) {
	// NOT IMPLEMENTED
}

func (c *XML) Remove(key string) {
	// NOT IMPLEMENTED
}

func (c *XML) Name() string {
	return "XML"
}

func (c *XML) Reset() {
	// NOT IMPLEMENTED
}
