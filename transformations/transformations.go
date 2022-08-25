// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3"
)

var transformations = map[string]coraza.RuleTransformation{}

// RegisterPlugin registers a transformation by name
// If the transformation is already registered, it will be overwritten
func RegisterPlugin(name string, trans coraza.RuleTransformation) {
	transformations[strings.ToLower(name)] = trans
}

// GetTransformation returns a transformation by name
// If the transformation is not found, it returns an error
func GetTransformation(name string) (coraza.RuleTransformation, error) {
	if t, ok := transformations[strings.ToLower(name)]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("invalid transformation name %q", name)
}

func init() {
	RegisterPlugin("base64Decode", base64decode)
	RegisterPlugin("cmdLine", cmdLine)
	RegisterPlugin("compressWhitespace", compressWhitespace)
	RegisterPlugin("cssDecode", cssDecode)
	RegisterPlugin("escapeSeqDecode", escapeSeqDecode)
	RegisterPlugin("hexEncode", hexEncode)
	RegisterPlugin("htmlEntityDecode", htmlEntityDecode)
	RegisterPlugin("jsDecode", jsDecode)
	RegisterPlugin("length", length)
	RegisterPlugin("lowercase", lowerCase)
	RegisterPlugin("md5", md5T)
	RegisterPlugin("none", none)
	RegisterPlugin("normalisePath", normalisePath)
	RegisterPlugin("normalisePathWin", normalisePathWin)
	RegisterPlugin("normalizePath", normalisePath)
	RegisterPlugin("normalizePathWin", normalisePathWin)
	RegisterPlugin("removeComments", removeComments)
	RegisterPlugin("removeCommentsChar", removeCommentsChar)
	RegisterPlugin("removeNulls", removeNulls)
	RegisterPlugin("removeWhitespace", removeWhitespace)
	RegisterPlugin("replaceComments", replaceComments)
	RegisterPlugin("replaceNulls", replaceNulls)
	RegisterPlugin("sha1", sha1T)
	RegisterPlugin("urlDecode", urlDecode)
	RegisterPlugin("urlDecodeUni", urlDecodeUni)
	RegisterPlugin("urlEncode", urlEncode)
	RegisterPlugin("utf8toUnicode", utf8ToUnicode)
}
