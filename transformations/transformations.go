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

package transformations

import (
	"fmt"

	"github.com/jptosso/coraza-waf/v2"
)

var transformations = map[string]coraza.RuleTransformation{}

func RegisterTransformation(name string, trans coraza.RuleTransformation) {
	transformations[name] = trans
}

// Get a transformation by name
func GetTransformation(name string) (coraza.RuleTransformation, error) {
	if t, ok := transformations[name]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("invalid transformation name %q", name)
}

func init() {
	RegisterTransformation("base64Decode", base64decode)
	RegisterTransformation("cmdLine", cmdLine)
	RegisterTransformation("compressWhitespace", compressWhitespace)
	RegisterTransformation("cssDecode", cssDecode)
	RegisterTransformation("escapeSeqDecode", escapeSeqDecode)
	RegisterTransformation("hexEncode", hexEncode)
	RegisterTransformation("htmlEntityDecode", htmlEntityDecode)
	RegisterTransformation("jsDecode", jsDecode)
	RegisterTransformation("length", length)
	RegisterTransformation("lowercase", lowerCase)
	RegisterTransformation("md5", md5T)
	RegisterTransformation("none", none)
	RegisterTransformation("normalisePath", normalisePath)
	RegisterTransformation("normalisePathWin", normalisePathWin)
	RegisterTransformation("normalizePath", normalisePath)
	RegisterTransformation("normalizePathWin", normalisePathWin)
	RegisterTransformation("removeComments", removeComments)
	RegisterTransformation("removeCommentsChar", removeCommentsChar)
	RegisterTransformation("removeNulls", removeNulls)
	RegisterTransformation("removeWhitespace", removeWhitespace)
	RegisterTransformation("replaceComments", replaceComments)
	RegisterTransformation("replaceNulls", replaceNulls)
	RegisterTransformation("sha1", sha1T)
	RegisterTransformation("urlDecode", urlDecode)
	RegisterTransformation("urlDecodeUni", urlDecodeUni)
	RegisterTransformation("urlEncode", urlEncode)
	RegisterTransformation("utf8toUnicode", utf8ToUnicode)
}
