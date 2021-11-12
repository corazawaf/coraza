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
	RegisterTransformation("base64Decode", Base64decode)
	RegisterTransformation("cmdLine", CmdLine)
	RegisterTransformation("compressWhitespace", CompressWhitespace)
	RegisterTransformation("cssDecode", CssDecode)
	RegisterTransformation("escapeSeqDecode", EscapeSeqDecode)
	RegisterTransformation("hexEncode", HexEncode)
	RegisterTransformation("htmlEntityDecode", HtmlEntityDecode)
	RegisterTransformation("jsDecode", JsDecode)
	RegisterTransformation("length", Length)
	RegisterTransformation("lowercase", LowerCase)
	RegisterTransformation("md5", Md5)
	RegisterTransformation("none", None)
	RegisterTransformation("normalisePath", NormalisePath)
	RegisterTransformation("normalisePathWin", NormalisePathWin)
	RegisterTransformation("normalizePath", NormalisePath)
	RegisterTransformation("normalizePathWin", NormalisePathWin)
	RegisterTransformation("removeComments", RemoveComments)
	RegisterTransformation("removeCommentsChar", RemoveCommentsChar)
	RegisterTransformation("removeNulls", RemoveNulls)
	RegisterTransformation("removeWhitespace", RemoveWhitespace)
	RegisterTransformation("replaceComments", ReplaceComments)
	RegisterTransformation("replaceNulls", ReplaceNulls)
	RegisterTransformation("sha1", Sha1)
	RegisterTransformation("urlDecode", UrlDecode)
	RegisterTransformation("urlDecodeUni", UrlDecodeUni)
	RegisterTransformation("urlEncode", UrlEncode)
	RegisterTransformation("utf8toUnicode", Utf8ToUnicode)
}
