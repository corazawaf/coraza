// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package collections

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestXMLPayload(t *testing.T) {
	data := `<?xml version="1.0"?>
<catalog>
   <book id="bk101">
      <author>Gambardella, Matthew</author>
      <title>XML Developer's Guide</title>
      <genre>Computer</genre>
      <price>44.95</price>
      <publish_date>2000-10-01</publish_date>
      <description>An in-depth look at creating applications 
      with XML.</description>
   </book>
   <book id="bk102">
      <author>Ralls, Kim</author>
      <title>Midnight Rain</title>
      <genre>Fantasy</genre>
      <price>5.95</price>
      <publish_date>2000-12-16</publish_date>
      <description>A former architect battles corporate zombies, 
      an evil sorceress, and her own childhood to become queen 
      of the world.</description>
   </book>
   <book id="bk103">
      <author>Corets, Eva</author>
      <title>Maeve Ascendant</title>
      <genre>Fantasy</genre>
      <price>5.95</price>
      <publish_date>2000-11-17</publish_date>
      <description>After the collapse of a nanotechnology 
      society in England, the young survivors lay the 
      foundation for a new society.</description>
   </book>
</catalog>`
	col := NewXML(variables.RequestXML)
	doc, err := decodeXML(data)
	if err != nil {
		t.Error(err)
	}
	col.SetDoc(doc)
	/*
		md := col.FindString("//@*")
		if len(md) > 0 {
			t.Error("Expected more than one match")
		}*/

}

func TestSmallXMLPayloda(t *testing.T) {
	data := `<?xml version="1.0"?><xml><element java.lang.runtime="attribute_value">element_value</element></xml>`
	col := NewXML(variables.RequestXML)
	doc, err := decodeXML(data)
	if err != nil {
		t.Error(err)
	}
	col.SetDoc(doc)
	md := col.FindString("//@*")
	md = append(md, col.FindString("//*")...)
	rx := regexp.MustCompile(`java\.lang\.(?:runtime|processbuilder)`)
	matches := 0
	for _, m := range md {
		fmt.Println(m.Value())
		if rx.MatchString(m.Value()) {
			matches++
		}
	}
	if matches == 0 {
		t.Error("Expected more than one match")
	}
}

var xmlOptions = xmlquery.DecoderOptions{
	Strict: false,
	Entity: xml.HTMLEntity,
}

func decodeXML(data string) (*xmlquery.Node, error) {
	opts := xmlquery.ParserOptions{
		Decoder: &xmlOptions,
	}
	doc, err := xmlquery.ParseWithOptions(strings.NewReader(data), opts)
	if err != nil {
		return nil, err
	}
	return doc, nil
}
