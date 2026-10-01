// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/collections"
)

type jsonBodyProcessor struct{}

var _ plugintypes.BodyProcessor = &jsonBodyProcessor{}

func (js *jsonBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, bpo plugintypes.BodyProcessorOptions) error {
	// Read the entire body into memory for two purposes:
	// 1. Store raw JSON in TX variables for operators like @validateSchema
	// 2. Parse and flatten for ARGS_POST collection
	s := strings.Builder{}
	if _, err := io.Copy(&s, reader); err != nil {
		return err
	}
	ss := s.String()
	// Process with recursion limit
	col := v.ArgsPost()
	data, truncated, err := readJSON(ss, bpo.RequestBodyRecursionLimit, bpo.ArgumentLimit)
	// The collection is populated before checking the error to still perform a best effort inspection of the payload.
	//
	// Add, not SetIndex: col is case-insensitive by default (and RESPONSE_ARGS
	// always is, regardless of build tags), so two flattened keys that differ
	// only by case -- e.g. "json.account.role" and "json.account.Role" --
	// fold to the same collection entry. SetIndex(key, i, value) lets each
	// one's independent index-0 write silently overwrite the other, since
	// neither call knows about the other key. Add always appends, so both
	// values survive under the collision exactly like a same-case collision
	// already does. See GHSA-5gj4-9gm7-2fx2.
	for key, values := range data {
		for _, value := range values {
			col.Add(key, value)
		}
	}
	if truncated {
		v.ArgumentsLimitReached().(*collections.Single).Set("1")
	}
	if err != nil {
		return err
	}

	// Store the raw JSON in the TX variable for validateSchema
	// This is needed because RequestBody is a Single interface without a Set method
	if txVar := v.TX(); txVar != nil {
		// Store the content type and raw body
		txVar.Set("json_request_body", []string{ss})
	}

	return nil
}

func (js *jsonBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, bpo plugintypes.BodyProcessorOptions) error {
	// Read the entire body to store it and process it
	s := strings.Builder{}
	if _, err := io.Copy(&s, reader); err != nil {
		return err
	}
	ss := s.String()
	// Process with recursion limit
	col := v.ResponseArgs()
	data, truncated, err := readJSON(ss, bpo.ResponseBodyRecursionLimit, bpo.ArgumentLimit)
	// The collection is populated before checking the error to still perform a best effort inspection of the payload.
	// See the comment in ProcessRequest: Add rather than SetIndex avoids a
	// case-insensitive collision silently overwriting one value (GHSA-5gj4-9gm7-2fx2).
	for key, values := range data {
		for _, value := range values {
			col.Add(key, value)
		}
	}
	if truncated {
		v.ArgumentsLimitReached().(*collections.Single).Set("1")
	}
	if err != nil {
		return err
	}

	// Store the raw JSON in the TX variable for validateSchema
	// This is needed because ResponseBody is a Single interface without a Set method
	if txVar := v.TX(); txVar != nil && v.ResponseBody() != nil {
		// Store the content type and raw body
		txVar.Set("json_response_body", []string{ss})
	}

	return nil
}

// readJSON flattens s into a map[string][]string, stopping once argumentLimit
// entries have been collected (argumentLimit <= 0 means no limit). Without
// this, a small body decoding to a wide flat structure (e.g. a JSON array of
// millions of scalars) grows this map -- and, through it, ARGS_POST/
// RESPONSE_ARGS -- without bound regardless of SecArgumentsLimit, exhausting
// memory on a single request. See GHSA-3ww9-vw83-9w5x.
// flattenBytesFactor bounds the flattened form relative to the body that
// produced it. SecArgumentsLimit counts entries, not bytes, and the flattened
// key is the full path rewritten for every leaf, so memory grows with
// depth x leaves while the entry count grows only with leaves. A body that
// stays comfortably under the argument limit can therefore still retain many
// times its own size: a 34 KB body of long paths measured 1.6 MB of keys at
// 999 arguments, roughly 48x, with no limit reached and no flag set.
//
// The factor is a judgement call rather than a derived number. Eight leaves
// room for genuinely nested documents -- measured well under 2x on ordinary
// API payloads -- while stopping the amplification well before it matters.
const flattenBytesFactor = 8

// flattenBytesFloor keeps small bodies unaffected, where a few long keys can
// legitimately outweigh the input.
const flattenBytesFloor = 4096

// errFlattenBudget stops the walk once the flattened form outgrows its budget.
var errFlattenBudget = errors.New("flattened json exceeds its byte budget")

// truncated only reports argumentLimit. Outgrowing the byte budget is an
// error, since raising SecArgumentsLimit does not help with it.
func readJSON(s string, maxRecursion int, argumentLimit int) (res map[string][]string, truncated bool, err error) {
	res = make(map[string][]string)
	key := []byte("json")

	byteBudget := len(s) * flattenBytesFactor
	if byteBudget < flattenBytesFloor {
		byteBudget = flattenBytesFloor
	}

	// The walk runs before the validity check on purpose: a body with a valid
	// prefix still populates ARGS on a best-effort basis, which rules can act
	// on even though an error is returned (see the best-effort tests, and
	// corazawaf/coraza#1615). What that ordering must not do is spend
	// unbounded time and memory flattening a body that is about to be
	// rejected -- byteBudget is what keeps that walk short.
	json := gjson.Parse(s)
	usedBytes := 0
	// argCount tracks the total number of values collected, not len(res):
	// a key collision (see GHSA-5gj4-9gm7-2fx2) appends more than one value
	// under the same flattened key, so counting distinct keys would let
	// SecArgumentsLimit undercount and admit more values than configured.
	argCount := 0
	// lenCount tracks the synthetic array-length entries separately, so an
	// array of exactly argumentLimit elements is not truncated by its own
	// length entry. It has the same cap, so the flattened map holds at most
	// 2*argumentLimit entries.
	lenCount := 0
	truncated, err = readItems(json, key, maxRecursion, argumentLimit, byteBudget, &usedBytes, &argCount, &lenCount, res)
	if errors.Is(err, errFlattenBudget) {
		return res, truncated, fmt.Errorf("flattened form exceeds the %d byte budget for a %d byte body", byteBudget, len(s))
	}
	if err != nil {
		return res, truncated, err
	}
	// readItems's own recursion guard never fires when argumentLimit
	// truncates the walk before it reaches a deeply nested tail:
	// the ForEach loop stops (truncated=true, err=nil) without ever
	// recursing into that tail, so maxRecursion is never checked against it.
	// gjson.Valid recurses with no depth bound at all (validany ->
	// validarray/validobject in gjson v1.18.0), so calling it unconditionally
	// on such a tail crashes the process with an unrecoverable
	// "fatal error: stack overflow" -- see GHSA-6gcq-wc29-5xf2. This iterative
	// check bounds that recursion before Valid ever runs.
	if jsonNestingExceedsLimit(s, maxRecursion) {
		return res, truncated, errors.New("max recursion reached while reading json object")
	}
	if !gjson.Valid(s) {
		return res, truncated, errors.New("invalid JSON")
	}
	return res, truncated, nil
}

// jsonNestingExceedsLimit reports whether s, read as raw JSON text, ever
// nests object/array containers deeper than limit. It is a single pass over
// the bytes with a depth counter -- no recursion -- so unlike gjson.Valid's
// recursive descent it cannot itself stack-overflow regardless of how deep
// (or how long) the input actually nests. It does not fully validate JSON
// syntax; that is still gjson.Valid's job once nesting is known to be safe.
func jsonNestingExceedsLimit(s string, limit int) bool {
	depth := 0
	inString := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > limit {
				return true
			}
		case '}', ']':
			depth--
		}
	}
	return false
}

// Transform JSON to a map[string][]string.
// This function is recursive and will call itself for nested objects.
// The limit in recursion is defined by maxItems.
// Example input: {"data": {"name": "John", "age": 30}, "items": [1,2,3]}
// Example output: map[string][]string{"json.data.name": {"John"}, "json.data.age": {"30"}, "json.items.0": {"1"}, "json.items.1": {"2"}, "json.items.2": {"3"}}
// Example input: [{"data": {"name": "John", "age": 30}, "items": [1,2,3]}]
// Example output: map[string][]string{"json.0.data.name": {"John"}, "json.0.data.age": {"30"}, "json.0.items.0": {"1"}, "json.0.items.1": {"2"}, "json.0.items.2": {"3"}}
//
// A nested path and a literal property name can flatten to the identical
// string (e.g. {"account":{"role":"x"}} and {"account.role":"y"} both
// produce "json.account.role"). Values are appended rather than overwritten
// on such a collision, so every value stays visible to rule inspection
// instead of a later property silently erasing an earlier one -- see
// GHSA-5gj4-9gm7-2fx2. The flattened key text itself is left unescaped:
// CRS rules such as 944130 match suspicious literal property names (e.g.
// Java class names used in deserialization attacks) as a substring of the
// generated key, and escaping would break that detection for the common,
// non-colliding case.
func readItems(json gjson.Result, objKey []byte, maxRecursion int, argumentLimit int, byteBudget int, usedBytes *int, argCount *int, lenCount *int, res map[string][]string) (truncated bool, err error) {
	if argumentLimit > 0 && *argCount >= argumentLimit {
		// Already at the configured SecArgumentsLimit: every recursive call
		// rechecks this up front, so once the limit is hit no further level
		// does any more work, regardless of how deeply nested the remainder
		// of the structure is.
		return true, nil
	}
	arrayLen := 0
	var iterationError error
	iterationTruncated := false
	if maxRecursion <= 0 {
		// We reached the limit of nesting we want to handle. This protects against
		// DoS attacks using deeply nested JSON structures (e.g., {"a":{"a":{"a":...}}}).
		return false, errors.New("max recursion reached while reading json object")
	}
	json.ForEach(func(key, value gjson.Result) bool {
		if argumentLimit > 0 && *argCount >= argumentLimit {
			iterationTruncated = true
			return false
		}
		// Avoid string concatenation to maintain a single buffer for key aggregation.
		prevParentLength := len(objKey)
		objKey = append(objKey, '.')
		if key.Type == gjson.String {
			objKey = append(objKey, key.Str...)
		} else {
			objKey = strconv.AppendInt(objKey, int64(key.Num), 10)
			arrayLen++
		}

		var val string
		switch value.Type {
		case gjson.JSON:
			// call recursively with one less item to avoid doing infinite recursion
			var nestedTruncated bool
			nestedTruncated, iterationError = readItems(value, objKey, maxRecursion-1, argumentLimit, byteBudget, usedBytes, argCount, lenCount, res)
			iterationTruncated = iterationTruncated || nestedTruncated
			if iterationError != nil {
				return false
			}
			objKey = objKey[:prevParentLength]
			return true
		case gjson.String:
			val = value.Str
		case gjson.Null:
			val = ""
		default:
			// For all other types, raw JSON is what we need
			val = value.Raw
		}

		// Checked per leaf, not only on entry to readItems: a wide object is
		// walked entirely inside one ForEach, so a guard at the top of the
		// function is never re-evaluated while these writes accumulate.
		if byteBudget > 0 && *usedBytes+len(objKey)+len(val) > byteBudget {
			// The flattened form has outgrown its budget; see flattenBytesFactor.
			iterationError = errFlattenBudget
			return false
		}

		k := string(objKey)
		res[k] = append(res[k], val)
		*usedBytes += len(objKey) + len(val)
		*argCount++
		objKey = objKey[:prevParentLength]

		return true
	})
	if arrayLen > 0 && iterationError == nil {
		// This write happens after ForEach has returned, so neither guard
		// inside the callback covers it. It needs both: a count cap, since
		// every array level adds an entry, and byteBudget, since each of those
		// entries repeats the full path. See GHSA-6r3q-mjv7-xr8m.
		//
		// The cap is lenCount, not argCount: length entries are not arguments
		// the client sent, so they must not use up SecArgumentsLimit. Running
		// out of them still sets truncated, or a body padded with [{}] could
		// silently hide the length of a later array from rules such as
		// ARGS_POST:json.items "@gt 100".
		if argumentLimit > 0 && *lenCount >= argumentLimit {
			iterationTruncated = true
		} else {
			lenStr := strconv.Itoa(arrayLen)
			if byteBudget > 0 && *usedBytes+len(objKey)+len(lenStr) > byteBudget {
				iterationError = errFlattenBudget
			} else {
				k := string(objKey)
				res[k] = append(res[k], lenStr)
				*usedBytes += len(objKey) + len(lenStr)
				*lenCount++
			}
		}
	}
	return iterationTruncated, iterationError
}

func init() {
	RegisterBodyProcessor("json", func() plugintypes.BodyProcessor {
		return &jsonBodyProcessor{}
	})
}
