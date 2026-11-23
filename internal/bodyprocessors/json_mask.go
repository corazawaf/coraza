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
//
// complete is false when not every value of s was seen: nesting went past
// maxRecursion, the keys outgrew the byte budget readJSON works under, a
// selected value could not be located, or s is not valid JSON. The caller must
// then treat the rest of s as unmasked.
func MaskJSONValues(s string, maxRecursion int, match func(key string) bool) (masked string, raw []string, complete bool) {
	w := jsonMaskWalk{
		s:      s,
		match:  match,
		budget: max(len(s)*flattenBytesFactor, flattenBytesFloor),
	}
	// The nesting check comes first because gjson.Valid recurses without a
	// bound, as in readJSON.
	complete = w.walk(gjson.Parse(s), []byte("json"), maxRecursion) &&
		!jsonNestingExceedsLimit(s, maxRecursion) && gjson.Valid(s)
	if len(w.spans) == 0 {
		return s, nil, complete
	}
	var b strings.Builder
	b.Grow(len(s))
	raw = make([]string, 0, len(w.spans))
	last := 0
	for _, span := range w.spans {
		b.WriteString(s[last:span[0]])
		b.WriteString(strings.Repeat("*", span[1]-span[0]))
		raw = append(raw, s[span[0]:span[1]])
		last = span[1]
	}
	b.WriteString(s[last:])
	return b.String(), raw, complete
}

type jsonMaskWalk struct {
	s     string
	match func(key string) bool
	// budget bounds the key and value bytes the walk handles, as byteBudget
	// does in readItems. Without it a long property name above a wide array
	// makes every element pay for the whole key again.
	budget int
	used   int
	spans  [][2]int
}

// walk collects the position in s of every scalar selected by match and
// reports whether it saw all of json. It builds keys the same way readItems
// does and must be kept in step with it.
func (w *jsonMaskWalk) walk(json gjson.Result, objKey []byte, maxRecursion int) bool {
	if maxRecursion <= 0 {
		return false
	}
	complete := true
	json.ForEach(func(key, value gjson.Result) bool {
		prevParentLength := len(objKey)
		objKey = append(objKey, '.')
		if key.Type == gjson.String {
			objKey = append(objKey, key.Str...)
		} else {
			objKey = strconv.AppendInt(objKey, int64(key.Num), 10)
		}
		if value.Type == gjson.JSON {
			complete = w.walk(value, objKey, maxRecursion-1)
			objKey = objKey[:prevParentLength]
			return complete
		}
		w.used += len(objKey) + len(value.Raw)
		if w.used > w.budget {
			complete = false
			return false
		}
		if value.Type != gjson.Null && w.match(string(objKey)) {
			start, end := value.Index, value.Index+len(value.Raw)
			if start < 0 || end > len(w.s) || w.s[start:end] != value.Raw {
				// gjson gave no usable position for a value that has to be masked.
				complete = false
				return false
			}
			if value.Type == gjson.String && end-start >= 2 && w.s[end-1] == '"' {
				start, end = start+1, end-1
			}
			if end > start {
				w.spans = append(w.spans, [2]int{start, end})
			}
		}
		objKey = objKey[:prevParentLength]
		return true
	})
	return complete
}
