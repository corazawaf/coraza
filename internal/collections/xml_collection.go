// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"fmt"
	"regexp"

	"github.com/antchfx/xmlquery"
	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// XML is a default collection.XML.
type XML struct {
	variable     variables.RuleVariable
	resultsCache map[string][]types.MatchData
	root         *xmlquery.Node
}

var _ collection.Map = &XML{}

func NewXML(variable variables.RuleVariable) *XML {
	return &XML{
		variable:     variable,
		resultsCache: map[string][]types.MatchData{},
	}
}

func (c *XML) SetDoc(root *xmlquery.Node) {
	c.root = root
}

func (c *XML) Get(key string) []string {
	return nil
}

func (c *XML) FindRegex(key *regexp.Regexp) []types.MatchData {
	// NOT IMPLEMENTED
	return nil
}

func (c *XML) FindString(xpath string) []types.MatchData {
	if c.root == nil {
		// XML not initialized
		return []types.MatchData{}
	}
	if _, ok := c.resultsCache[xpath]; ok {
		return c.resultsCache[xpath]
	}
	md := []types.MatchData{}
	/*
		From CRS samples:
		- //@* returns all attributes, the key for each element should be the element name
		  The value should be the inner content (attribute="value")
		- //* returns all elements, the key for each element should be the element name
	*/
	results, err := xmlquery.QueryAll(c.root, xpath)
	if err != nil {
		// invalid xpath expression, we don't have any way of logging here
		c.resultsCache[xpath] = md
		return md
	}
	for _, n := range results {
		switch n.Type {
		case xmlquery.ElementNode:
			// Value should be inner content
			md = append(md, &corazarules.MatchData{
				Variable_: c.variable,
				Key_:      computePath(n.Parent),
				Value_:    n.InnerText(),
			})
		case xmlquery.AttributeNode:
			// Value should be attribute="value"
			md = append(md, &corazarules.MatchData{
				Variable_: c.variable,
				Key_:      computePath(n.Parent),
				Value_:    fmt.Sprintf("%s=%q", n.Data, n.InnerText()),
			})
		}
	}
	// we store the cache
	c.resultsCache[xpath] = md
	return md
}

func computePath(n *xmlquery.Node) string {
	path := ""
	for n != nil {
		path = "/" + n.Data + path
		n = n.Parent
	}
	return path
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
	return c.variable.Name()
}

func (c *XML) Reset() {
	// NOT IMPLEMENTED
}
