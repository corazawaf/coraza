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

type Transformation = func(input string) string

func TransformationsMap() map[string]Transformation {
	return map[string]Transformation{
		"base64Decode": Base64decode,
		//BEGIN NON WORKING
		"escapeSeqDecode":    EscapeSeqDecode,
		"removeCommentsChar": None,
		//END NON WORKING
		"lowercase":          LowerCase,
		"removeWhitespace":   RemoveWhitespace,
		"removeNulls":        RemoveNulls,
		"replaceNulls":       ReplaceNulls,
		"compressWhitespace": CompressWhitespace,
		"none":               None,
		"sha1":               Sha1,
		"md5":                Md5,
		"urlDecode":          UrlDecode,
		"urlEncode":          UrlEncode,
		"urlDecodeUni":       UrlDecodeUni,
		"utf8toUnicode":      Utf8ToUnicode,
		"replaceComments":    ReplaceComments,
		"removeComments":     RemoveComments,
		"htmlEntityDecode":   HtmlEntityDecode,
		"cssDecode":          CssDecode,
		"jsDecode":           JsDecode,
		"cmdLine":            CmdLine,
		"length":             Length,
		"hexEncode":          HexEncode,
		"normalizePath":      NormalisePath,
		"normalisePath":      NormalisePath,
		"normalizePathWin":   NormalisePathWin,
		"normalisePathWin":   NormalisePathWin,
	}
}
