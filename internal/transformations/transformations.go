// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import "github.com/corazawaf/coraza/v3/experimental/plugins"

func init() {
	plugins.RegisterTransformation("base64Decode", base64decode)
	plugins.RegisterTransformation("cmdLine", cmdLine)
	plugins.RegisterTransformation("compressWhitespace", compressWhitespace)
	plugins.RegisterTransformation("cssDecode", cssDecode)
	plugins.RegisterTransformation("escapeSeqDecode", escapeSeqDecode)
	plugins.RegisterTransformation("hexEncode", hexEncode)
	plugins.RegisterTransformation("htmlEntityDecode", htmlEntityDecode)
	plugins.RegisterTransformation("jsDecode", jsDecode)
	plugins.RegisterTransformation("length", length)
	plugins.RegisterTransformation("lowercase", lowerCase)
	plugins.RegisterTransformation("md5", md5T)
	plugins.RegisterTransformation("none", none)
	plugins.RegisterTransformation("normalisePath", normalisePath)
	plugins.RegisterTransformation("normalisePathWin", normalisePathWin)
	plugins.RegisterTransformation("normalizePath", normalisePath)
	plugins.RegisterTransformation("normalizePathWin", normalisePathWin)
	plugins.RegisterTransformation("removeComments", removeComments)
	plugins.RegisterTransformation("removeCommentsChar", removeCommentsChar)
	plugins.RegisterTransformation("removeNulls", removeNulls)
	plugins.RegisterTransformation("removeWhitespace", removeWhitespace)
	plugins.RegisterTransformation("replaceComments", replaceComments)
	plugins.RegisterTransformation("replaceNulls", replaceNulls)
	plugins.RegisterTransformation("sha1", sha1T)
	plugins.RegisterTransformation("urlDecode", urlDecode)
	plugins.RegisterTransformation("urlDecodeUni", urlDecodeUni)
	plugins.RegisterTransformation("urlEncode", urlEncode)
	plugins.RegisterTransformation("utf8toUnicode", utf8ToUnicode)
}
