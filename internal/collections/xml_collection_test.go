// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"
	"testing"

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
	if err := col.SetDoc(strings.NewReader(data)); err != nil {
		t.Error(err)
	}
	md := col.FindString("//@*")
	if len(md) == 0 {
		t.Error("Expected more than one match")
	}
	/*
		md2 := col.FindString("//@*")
		if unsafe.Pointer(&md[0]) != unsafe.Pointer(&md2[0]) {
			t.Error("Expected same pointer because of cache")
		}
	*/
	md = col.FindString("/*")
	if len(md) == 0 {
		t.Error("Expected more than one match")
	}

}

func TestXMLSimple(t *testing.T) {
	data := "<?xml version=\"1.0\"?><xml><processbuilder.evil.prototypeclonefactory attribute_name=\"attribute_value\">value</processbuilder.evil.prototypeclonefactory></xml>"
	col := NewXML(variables.RequestXML)
	if err := col.SetDoc(strings.NewReader(data)); err != nil {
		t.Error(err)
	}
	md := col.FindString("/*")
	md = append(md, col.FindString("//@*")...)
	matches := 0
	rx := regexp.MustCompile("(?:clonetransformer|forclosure|instantiatefactory|instantiatetransformer|invokertransformer|prototypeclonefactory|prototypeserializationfactory|whileclosure|getproperty|filewriter|xmldecoder)")
	for _, m := range md {
		if rx.MatchString(m.Value()) {
			matches++
		}
	}
	if matches > 0 {
		t.Error("Expected no matches")
	}
}
