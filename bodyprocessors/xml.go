// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package bodyprocessors

import (
	"encoding/xml"
	"io"

	"github.com/antchfx/xmlquery"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/rules"
)

var xmlOptions = xmlquery.DecoderOptions{
	Strict:    false,
	AutoClose: xml.HTMLAutoClose,
	Entity:    xml.HTMLEntity,
}

type xmlBodyProcessor struct {
}

func (*xmlBodyProcessor) ProcessRequest(reader io.Reader, v rules.TransactionVariables, options Options) error {
	x := v.RequestXML().(*collections.XML)
	doc, err := decodeXML(reader)
	if err != nil {
		return err
	}
	x.SetDoc(doc)
	return nil
}

func (*xmlBodyProcessor) ProcessResponse(reader io.Reader, v rules.TransactionVariables, options Options) error {
	x := v.ResponseXML().(*collections.XML)
	doc, err := decodeXML(reader)
	if err != nil {
		return err
	}
	x.SetDoc(doc)
	return nil
}

func decodeXML(reader io.Reader) (*xmlquery.Node, error) {
	opts := xmlquery.ParserOptions{
		Decoder: &xmlOptions,
	}
	doc, err := xmlquery.ParseWithOptions(reader, opts)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

var (
	_ BodyProcessor = &xmlBodyProcessor{}
)

func init() {
	Register("xml", func() BodyProcessor {
		return &xmlBodyProcessor{}
	})
}
