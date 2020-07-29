package transformations

func TransformationsMap() map[string]interface{} {
	return map[string]interface{}{
		"base64Decode":       Base64decode,
		"lowercase":          LowerCase,
		"removeWhitespace":   RemoveWhitespace,
		"removeNulls":        RemoveNulls,
		"replaceNulls":       ReplaceNulls,
		"compressWhitespace": CompressWhitespace,
		"none":               None,
		"sha1":               Sha1,
		"urlDecode":          UrlDecode,
		"urlEncode":          UrlEncode,
		"urlDecodeUni":       UrlDecodeUni,
		"utf8toUnicode":      Utf8ToUnicode,
		"replaceComments":    ReplaceComments,
		"htmlEntityDecode":   HtmlEntityDecode,
		//"cssDecode": CssDecode,
		//"jsDecode": JsDecode,
		"cmdLine":          CmdLine,
		"length":           Length,
		"hexEncode":        HexEncode,
		"normalizePath":    NormalisePath,
		"normalisePath":    NormalisePath,
		"normalizePathWin": NormalisePathWin,
	}
}