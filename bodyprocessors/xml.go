//go:build !tinygo
// +build !tinygo

// Copyright 2022 The CorazaWAF Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	col := collections[variables.RequestXML].(*collection.CollectionMap)
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
