// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"

	"github.com/antchfx/xmlquery"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// XPathMap implements collection.Map with lazy XPath evaluation against
// a parsed XML document. XPath expressions are evaluated on demand when
// FindString, FindRegex, or Get are called.
type XPathMap struct {
	doc      *xmlquery.Node
	variable variables.RuleVariable
}

var _ collection.Map = &XPathMap{}

// NewXPathMap creates a new XPathMap backed by the given XML document.
func NewXPathMap(variable variables.RuleVariable, doc *xmlquery.Node) *XPathMap {
	return &XPathMap{
		doc:      doc,
		variable: variable,
	}
}

// evalXPath evaluates an XPath expression against the document and returns
// the string values of matching nodes.
func (c *XPathMap) evalXPath(expr string) []string {
	if c.doc == nil {
		return nil
	}
	nodes, err := xmlquery.QueryAll(c.doc, expr)
	if err != nil {
		return nil
	}
	if len(nodes) == 0 {
		return nil
	}
	results := make([]string, 0, len(nodes))
	for _, n := range nodes {
		text := n.InnerText()
		if trimmed := strings.TrimSpace(text); trimmed != "" {
			results = append(results, trimmed)
		}
	}
	return results
}

// Get evaluates the given XPath expression against the parsed XML document
// and returns the string values of all matching nodes.
func (c *XPathMap) Get(key string) []string {
	return c.evalXPath(key)
}

// FindString evaluates the given XPath expression against the parsed XML
// document and returns MatchData for each matching node. If key is empty,
// it delegates to FindAll.
func (c *XPathMap) FindString(key string) []types.MatchData {
	if key == "" {
		return c.FindAll()
	}
	values := c.evalXPath(key)
	if len(values) == 0 {
		return nil
	}
	buf := make([]corazarules.MatchData, len(values))
	result := make([]types.MatchData, len(values))
	for i, v := range values {
		buf[i] = corazarules.MatchData{
			Variable_: c.variable,
			Key_:      key,
			Value_:    v,
		}
		result[i] = &buf[i]
	}
	return result
}

// FindRegex returns all document nodes whose XPath key matches the given
// regular expression. Since regex is not meaningful over XPath expressions,
// this falls back to FindAll and filters results by key.
func (c *XPathMap) FindRegex(key *regexp.Regexp) []types.MatchData {
	all := c.FindAll()
	var result []types.MatchData
	for _, m := range all {
		if key.MatchString(m.Key()) {
			result = append(result, m)
		}
	}
	return result
}

// FindAll returns all text content and attribute values from the document,
// equivalent to evaluating //@* and //* text nodes.
func (c *XPathMap) FindAll() []types.MatchData {
	var result []types.MatchData
	result = append(result, c.FindString("//@*")...)
	result = append(result, c.FindString("//*[text()]")...)
	return result
}

// Set is a no-op for XPathMap. The underlying data comes from the parsed
// XML DOM and is not mutable through this interface.
func (c *XPathMap) Set(key string, values []string) {}

// Add is a no-op for XPathMap. See Set for rationale.
func (c *XPathMap) Add(key string, value string) {}

// SetIndex is a no-op for XPathMap. See Set for rationale.
func (c *XPathMap) SetIndex(key string, index int, value string) {}

// Remove is a no-op for XPathMap. See Set for rationale.
func (c *XPathMap) Remove(key string) {}

// Name returns the name of the variable this collection is bound to.
func (c *XPathMap) Name() string {
	return c.variable.Name()
}

// Reset clears the document reference.
func (c *XPathMap) Reset() {
	c.doc = nil
}

// Format writes a string representation of the collection.
func (c *XPathMap) Format(res *strings.Builder) {
	res.WriteString(c.variable.Name())
	res.WriteString(": (xmlquery xpath-backed collection)\n")
}
