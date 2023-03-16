//go:build !tinygo
// +build !tinygo

// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0
package collections

import (
	"encoding/xml"
	"io"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// XML is a default collection.XML.
type XML struct {
	variable   variables.RuleVariable
	attributes []types.MatchData
	content    []types.MatchData
}

var _ collection.Map = &XML{}

func NewXML(variable variables.RuleVariable) *XML {
	return &XML{
		variable:   variable,
		attributes: make([]types.MatchData, 0),
		content:    make([]types.MatchData, 0),
	}
}

func (c *XML) SetDoc(reader io.Reader) error {
	attrs, content, err := readXML(reader)
	if err != nil {
		return err
	}
	for _, attr := range attrs {
		c.attributes = append(c.attributes, &corazarules.MatchData{
			Variable_: c.variable,
			Key_:      "//@*",
			Value_:    attr,
		})
	}
	for _, cn := range content {
		c.content = append(c.content, &corazarules.MatchData{
			Variable_: c.variable,
			Key_:      "/*",
			Value_:    cn,
		})
	}

	return nil
}

func (c *XML) Get(key string) []string {
	return nil
}

func (c *XML) FindRegex(key *regexp.Regexp) []types.MatchData {
	// NOT IMPLEMENTED
	return nil
}

func (c *XML) FindString(xpath string) []types.MatchData {
	if xpath == "//@*" {
		return c.attributes
	} else if xpath == "/*" {
		return c.content
	}
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
	return c.variable.Name()
}

func readXML(reader io.Reader) ([]string, []string, error) {
	var attrs []string
	var content []string
	dec := xml.NewDecoder(reader)
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity
	for {
		token, err := dec.Token()
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		if token == nil {
			break
		}
		switch tok := token.(type) {
		case xml.StartElement:
			for _, attr := range tok.Attr {
				attrs = append(attrs, attr.Value)
			}
		case xml.CharData:
			if c := strings.TrimSpace(string(tok)); c != "" {
				content = append(content, c)
			}
		}
	}
	return attrs, content, nil
}

var _ collection.Map = &XML{}
