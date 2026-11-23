// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

// MaskJSONValues returns s with the raw text of every scalar whose flattened
// key satisfies match replaced by asterisks, one per byte, together with the
// raw texts it masked. Keys are the ones readItems gives ARGS_POST, so values
// can be selected by argument name. Masking works on the raw text, so a value
// is masked however it is escaped. The quotes of a string are kept.
func MaskJSONValues(s string, maxRecursion int, match func(key string) bool) (string, []string) {
	var spans [][2]int
	jsonValueSpans(s, gjson.Parse(s), []byte("json"), maxRecursion, match, &spans)
	if len(spans) == 0 {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	masked := make([]string, 0, len(spans))
	last := 0
	for _, span := range spans {
		b.WriteString(s[last:span[0]])
		b.WriteString(strings.Repeat("*", span[1]-span[0]))
		masked = append(masked, s[span[0]:span[1]])
		last = span[1]
	}
	b.WriteString(s[last:])
	return b.String(), masked
}

// jsonValueSpans collects the position in s of every scalar selected by match.
// It builds keys the same way readItems does and must be kept in step with it.
func jsonValueSpans(s string, json gjson.Result, objKey []byte, maxRecursion int, match func(key string) bool, spans *[][2]int) {
	if maxRecursion <= 0 {
		return
	}
	json.ForEach(func(key, value gjson.Result) bool {
		prevParentLength := len(objKey)
		objKey = append(objKey, '.')
		if key.Type == gjson.String {
			objKey = append(objKey, key.Str...)
		} else {
			objKey = strconv.AppendInt(objKey, int64(key.Num), 10)
		}
		switch value.Type {
		case gjson.JSON:
			jsonValueSpans(s, value, objKey, maxRecursion-1, match, spans)
		case gjson.Null:
		default:
			start, end := value.Index, value.Index+len(value.Raw)
			// gjson gives no position for some results; without one the value
			// is left to the caller's masking by value.
			if start >= 0 && end <= len(s) && s[start:end] == value.Raw && match(string(objKey)) {
				if value.Type == gjson.String && end-start >= 2 && s[end-1] == '"' {
					start, end = start+1, end-1
				}
				if end > start {
					*spans = append(*spans, [2]int{start, end})
				}
			}
		}
		objKey = objKey[:prevParentLength]
		return true
	})
}
