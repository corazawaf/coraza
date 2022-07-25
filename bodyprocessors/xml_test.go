// Copyright 2022 Juan Pablo Tosso
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
	"bytes"
	"testing"

	"github.com/corazawaf/coraza/v2/utils/strings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

	require.Len(t, attrs, 3)
	require.Len(t, contents, 4)

	eattrs := []string{"en", "value"}
	econtent := []string{"Harry Potter", "29.99", "Learning XML", "39.95"}
	for _, attr := range eattrs {
		assert.True(t, strings.InSlice(attr, attrs), "expected to contain attribute %q, got %v", attr, attrs)
	}

	for _, content := range econtent {
		assert.True(t, strings.InSlice(content, contents), "expected content %q, got %v", content, contents)
	}
}
