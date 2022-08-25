// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package bodyprocessors

import (
	"encoding/xml"
	"io"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, collections [types.VariablesCount]collection.Collection, options Options) error {
	values, contents, err := readXML(reader)
	if err != nil {
		return err
	}
	col := collections[variables.RequestXML].(*collection.Map)
	col.Set("//@*", values)
	col.Set("/*", contents)
	return nil
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, collections [types.VariablesCount]collection.Collection, options Options) error {

	return nil
}

func readXML(reader io.Reader) (attrs []string, content []string, err error) {
	dec := xml.NewDecoder(reader)
	var n xmlNode
	err = dec.Decode(&n)
	if err != nil {
		return
	}
	xmlWalk([]xmlNode{n}, func(n xmlNode) bool {
		a := n.Attrs
		for _, attr := range a {
			attrs = append(attrs, attr.Value)
		}
		if len(n.Nodes) == 0 {
			content = append(content, string(n.Content))
		}
		return true
	})
	return
}

func xmlWalk(nodes []xmlNode, f func(xmlNode) bool) {
	for _, n := range nodes {
		if f(n) {
			xmlWalk(n.Nodes, f)
		}
	}
}

type xmlNode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Content []byte     `xml:",innerxml"`
	Nodes   []xmlNode  `xml:",any"`
}

var (
	_ BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	Register("xml", func() BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
