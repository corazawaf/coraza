// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package bodyprocessors

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/strings"
)

func TestXMLAttribures(t *testing.T) {
	xmldoc := `<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
<book>
  <title lang="en">Harry Potter</title>
  <price secret="value">29.99</price>
</book>

<book>
  <title lang="en">Learning XML</title>
  <price>39.95</price>
</book>

</bookstore>`
	attrs, contents, err := readXML(bytes.NewReader([]byte(xmldoc)))
	if err != nil {
		t.Error(err)
	}
	if len(attrs) != 3 {
		t.Errorf("Expected 3 attributes, got %d", len(attrs))
	}
	if len(contents) != 4 {
		t.Errorf("Expected 4 contents, got %d", len(contents))
		fmt.Println(contents)
	}
	eattrs := []string{"en", "value"}
	econtent := []string{"Harry Potter", "29.99", "Learning XML", "39.95"}
	for _, attr := range eattrs {
		if !strings.InSlice(attr, attrs) {
			t.Errorf("Expected attribute %s, got %v", attr, attrs)
		}
	}
	for _, content := range econtent {
		if !strings.InSlice(content, contents) {
			t.Errorf("Expected content %s, got %v", content, contents)
		}
	}
}
