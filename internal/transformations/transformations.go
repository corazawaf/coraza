// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package transformations

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

var transformations = map[string]plugintypes.Transformation{}

// Register registers a transformation by name
// If the transformation is already registered, it will be overwritten
func Register(name string, trans plugintypes.Transformation) {
	transformations[strings.ToLower(name)] = trans
}

// GetTransformation returns a transformation by name
// If the transformation is not found, it returns an error
func GetTransformation(name string) (plugintypes.Transformation, error) {
	if t, ok := transformations[strings.ToLower(name)]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("invalid transformation name %q", name)
}

func init() {
	Register("base64Decode", base64decode)
	Register("cmdLine", cmdLine)
	Register("compressWhitespace", compressWhitespace)
	Register("cssDecode", cssDecode)
	Register("escapeSeqDecode", escapeSeqDecode)
	Register("hexEncode", hexEncode)
	Register("htmlEntityDecode", htmlEntityDecode)
	Register("jsDecode", jsDecode)
	Register("length", length)
	Register("lowercase", lowerCase)
	Register("md5", md5T)
	Register("none", none)
	Register("normalisePath", normalisePath)
	Register("normalisePathWin", normalisePathWin)
	Register("normalizePath", normalisePath)
	Register("normalizePathWin", normalisePathWin)
	Register("removeComments", removeComments)
	Register("removeCommentsChar", removeCommentsChar)
	Register("removeNulls", removeNulls)
	Register("removeWhitespace", removeWhitespace)
	Register("replaceComments", replaceComments)
	Register("replaceNulls", replaceNulls)
	Register("sha1", sha1T)
	Register("urlDecode", urlDecode)
	Register("urlDecodeUni", urlDecodeUni)
	Register("urlEncode", urlEncode)
	Register("utf8toUnicode", utf8ToUnicode)
	Register("trim", trim)
	Register("trimLeft", trimLeft)
	Register("trimRight", trimRight)
}
