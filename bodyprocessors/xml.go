// Copyright 2021 Juan Pablo Tosso
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

	"github.com/jptosso/coraza-waf/v2/types/variables"
)

// This is only intended for compatibility, xpath is not supported
// This hack should work for OWASP CRS
// This skeleton may be used for other plugins
type xmlBodyProcessor struct {
	values   []string
	contents []string
}

func (xbp *xmlBodyProcessor) Read(reader io.Reader, _ string, _ string) error {
	var err error
	xbp.values, xbp.contents, err = readXML(reader)
	return err
}

func (xbp *xmlBodyProcessor) Collections() collectionsMap {
	return collectionsMap{}
}

func (xbp *xmlBodyProcessor) Find(expr string) (map[string][]string, error) {
	switch expr {
	case "//@*":
		// attribute values
		return map[string][]string{"": xbp.values}, nil
	case "/*":
		// inner text
		return map[string][]string{"": xbp.contents}, nil
	default:
		// unsupported expression
		return nil, nil
	}
}

func (xbp *xmlBodyProcessor) VariableHook() variables.RuleVariable {
	return variables.XML
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
