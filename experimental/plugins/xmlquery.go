// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"io"

	"github.com/antchfx/xmlquery"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/experimental/plugins/collections"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/types/variables"
)

// xmlSettableVariables is an optional interface that TransactionVariables may
// implement to allow body processors to replace the XML collection with a
// custom implementation. This decouples the body processor from the concrete
// transaction type.
type xmlSettableVariables interface {
	SetRequestXML(collection.Map)
}

// xmlQueryBodyProcessor parses XML request bodies into an in-memory DOM and
// installs a lazy XPath collection (collections.XPathMap) as the RequestXML
// variable. XPath expressions in rules (e.g. XML:/soap:Envelope/soap:Body)
// are evaluated on demand against the parsed document, rather than requiring
// pre-computed keys.
type xmlQueryBodyProcessor struct{}

var _ plugintypes.BodyProcessor = (*xmlQueryBodyProcessor)(nil)

// ProcessRequest parses the request body as XML and installs a lazy XPath
// collection on the transaction's RequestXML variable. If the transaction
// does not support SetRequestXML, it falls back to populating the standard
// //@* and /* keys on the existing collection.
func (*xmlQueryBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	doc, err := xmlquery.Parse(reader)
	if err != nil {
		return err
	}

	// If the transaction supports swapping the XML collection, install the
	// lazy XPath-backed collection. Otherwise, fall back to populating the
	// existing map with the two standard keys.
	if setter, ok := v.(xmlSettableVariables); ok {
		xpathMap := collections.NewXPathMap(variables.RequestXML, doc)
		setter.SetRequestXML(xpathMap)
	} else {
		col := v.RequestXML()
		attrs, contents := extractFromDoc(doc)
		col.Set("//@*", attrs)
		col.Set("/*", contents)
	}

	return nil
}

// ProcessResponse is not yet implemented for XML response bodies.
func (*xmlQueryBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

// extractFromDoc walks the parsed DOM and extracts all attribute values and
// text content, mirroring the behavior of the original xml body processor.
func extractFromDoc(doc *xmlquery.Node) (attrs []string, content []string) {
	nodes, _ := xmlquery.QueryAll(doc, "//@*")
	for _, n := range nodes {
		if v := n.InnerText(); v != "" {
			attrs = append(attrs, v)
		}
	}
	textNodes, _ := xmlquery.QueryAll(doc, "//*[text()]")
	for _, n := range textNodes {
		if v := n.InnerText(); v != "" {
			content = append(content, v)
		}
	}
	return attrs, content
}

func init() {
	bodyprocessors.RegisterBodyProcessor("xmlquery", func() plugintypes.BodyProcessor {
		return &xmlQueryBodyProcessor{}
	})
}
