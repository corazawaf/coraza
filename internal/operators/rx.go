// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.rx

package operators

import (
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"

	"rsc.io/binaryregexp"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs regular expression pattern matching using RE2 syntax. This is the default operator
// if no @ prefix is specified. Supports capturing groups (up to 9) for use in rule actions.
// By default enables dotall mode (?s) where . matches newlines for compatibility with ModSecurity.
//
// Arguments:
// Regular expression pattern following RE2 syntax. The pattern is automatically wrapped with
// mode flags for proper matching behavior.
//
// Returns:
// true if the pattern matches the input, false otherwise
//
// Example:
// ```
// # Match User-Agent containing "nikto" (with explicit @rx)
// SecRule REQUEST_HEADERS:User-Agent "@rx nikto" "id:180,deny,log"
//
// # Implicit operator usage (same as @rx)
// SecRule ARGS "(?i)union.*select" "id:181,deny"
//
// # Capture groups for reuse in actions
// SecRule REQUEST_URI "@rx ^/api/v(\d+)" "id:182,setvar:tx.api_version=%{TX.1}"
// ```
type rx struct {
	re           *regexp.Regexp
	minLen       int
	prefilter    func(string) bool // returns true if regex might match; nil = no prefilter
	exactMatch   string            // non-empty: pattern is ^literal$; skip NFA entirely
	exactMatchCI bool              // true when exactMatch uses case-insensitive comparison
}

// rxCompiled holds all compile-time artifacts for a regex pattern so they can
// be computed once and shared via memoize when the same pattern appears in
// multiple rules.
type rxCompiled struct {
	re           *regexp.Regexp
	minLen       int
	prefilter    func(string) bool
	exactMatch   string
	exactMatchCI bool
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	var data string
	if shouldNotUseMultilineRegexesOperatorByDefault {
		// (?s) enables dotall mode, required by some CRS rules and matching ModSec behavior, see
		// - https://github.com/google/re2/wiki/Syntax
		// - Flag usage: https://groups.google.com/g/golang-nuts/c/jiVdamGFU9E
		data = fmt.Sprintf("(?s)%s", options.Arguments)
	} else {
		// TODO: deprecate multiline modifier set by default in Coraza v4
		// CRS rules will explicitly set the multiline modifier when needed
		// Having it enabled by default can lead to false positives and less performance
		// See https://github.com/corazawaf/coraza/pull/876
		data = fmt.Sprintf("(?sm)%s", options.Arguments)
	}

	if matchesArbitraryBytes(data) {
		// Use binary regex matcher if expression matches non-utf8 bytes. The binary matcher does
		// not match unicode, meaning we cannot support expressions with both unicode and non-utf8
		// matches. This should not be commonly needed.
		return newBinaryRX(options)
	}

	// Compile regex + prefilter together so memoize caches all artifacts as one
	// unit. This avoids re-parsing the AST for minMatchLength/prefilterFunc when
	// the same pattern appears in multiple rules.
	//
	// The prefilter flag is part of the key because the global cache is shared
	// across all WAF instances: two WAFs with different SecRxPreFilter settings
	// must not share a compiled artifact.
	cacheKey := fmt.Sprintf("rx:%v:%s", options.RxPreFilterEnabled, data)
	compiled, err := memoizeDo(options.Memoizer, cacheKey, func() (any, error) {
		re, err := regexp.Compile(data)
		if err != nil {
			return nil, err
		}
		c := &rxCompiled{re: re}
		if options.RxPreFilterEnabled {
			c.minLen = minMatchLength(data)
			c.prefilter = prefilterFunc(data)
			// Gap 2: detect pure ^literal$ patterns and bypass the NFA entirely.
			// Parse options.Arguments (the original, un-wrapped pattern) so that
			// ^ is OpBeginText and $ is OpEndText — without the (?m) flag that
			// newRX prepends, which would convert them to OpBeginLine/OpEndLine
			// and make position-0 reasoning unsound.
			if origParsed, err2 := syntax.Parse(options.Arguments, syntax.Perl); err2 == nil {
				if lit, ci := extractExactMatch(origParsed.Simplify()); lit != "" {
					c.exactMatch = lit
					c.exactMatchCI = ci
				}
			}
		}
		return c, nil
	})
	if err != nil {
		return nil, err
	}
	c := compiled.(*rxCompiled)
	return &rx{
		re:           c.re,
		minLen:       c.minLen,
		prefilter:    c.prefilter,
		exactMatch:   c.exactMatch,
		exactMatchCI: c.exactMatchCI,
	}, nil
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	// Prefiltering evaluation is performed here, skipping regex evaluation for clearly non-matching inputs.
	if len(value) < o.minLen {
		return false
	}
	if o.prefilter != nil && !o.prefilter(value) {
		return false
	}
	// Gap 2: exact-match bypass for patterns like ^Upload$ — skip the NFA entirely.
	// The \n guard protects against multi-line inputs where (?m)$ matches
	// before a newline (e.g. "Upload\nmore" would satisfy (?sm)^Upload$).
	if o.exactMatch != "" && !strings.ContainsRune(value, '\n') {
		if o.exactMatchCI {
			return strings.EqualFold(value, o.exactMatch)
		}
		return value == o.exactMatch
	}

	if tx.Capturing() {
		// FindStringSubmatchIndex returns a slice of index pairs [start0, end0, start1, end1, ...]
		// instead of allocating new strings for each capture group. We then slice the original
		// input value[start:end] to get zero-allocation substrings.
		match := o.re.FindStringSubmatchIndex(value)
		if match == nil {
			return false
		}
		// match has 2 entries per group: match[2*i] is the start index,
		// match[2*i+1] is the end index for capture group i. Group 0 is
		// the full match, groups 1..N are the parenthesized sub-expressions.
		for i := 0; i < len(match)/2; i++ {
			if i == 9 {
				return true
			}
			// A negative start index means the group did not participate in the match
			// (e.g. an optional group like (foo)? when foo is absent).
			if match[2*i] >= 0 {
				tx.CaptureField(i, value[match[2*i]:match[2*i+1]])
			} else {
				tx.CaptureField(i, "")
			}
		}
		return true
	} else {
		return o.re.MatchString(value)
	}
}

// binaryRx is exactly the same as rx, but using the binaryregexp package for matching
// arbitrary bytes.
type binaryRX struct {
	re *binaryregexp.Regexp
}

var _ plugintypes.Operator = (*binaryRX)(nil)

func newBinaryRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	re, err := memoizeDo(options.Memoizer, data, func() (any, error) { return binaryregexp.Compile(data) })
	if err != nil {
		return nil, err
	}
	return &binaryRX{re: re.(*binaryregexp.Regexp)}, nil
}

func (o *binaryRX) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if tx.Capturing() {
		match := o.re.FindStringSubmatch(value)
		if len(match) == 0 {
			return false
		}
		for i, c := range match {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
		return true
	} else {
		return o.re.MatchString(value)
	}
}

func init() {
	Register("rx", newRX)
}

// matchesArbitraryBytes checks for control sequences for byte matches in the expression.
// If the sequences are not valid utf8, it returns true.
func matchesArbitraryBytes(expr string) bool {
	decoded := make([]byte, 0, len(expr))
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c != '\\' {
			decoded = append(decoded, c)
			continue
		}
		if i+3 >= len(expr) {
			decoded = append(decoded, expr[i:]...)
			break
		}
		if expr[i+1] != 'x' {
			decoded = append(decoded, expr[i])
			continue
		}

		// Handle braced hex escapes like \x{bc} by converting to the
		// unbraced form \xbc so strconv.UnquoteChar can parse them.
		sub := expr[i:]
		advance := 3 // default for \xNN (4 chars total, skip 3 extra)
		if len(sub) >= 6 && sub[2] == '{' {
			if end := strings.IndexByte(sub, '}'); end != -1 {
				sub = `\x` + sub[3:end]
				advance = end
			}
		}

		v, mb, _, err := strconv.UnquoteChar(sub, 0)
		if err != nil || mb {
			// Wasn't a byte escape sequence, shouldn't happen in practice.
			decoded = append(decoded, expr[i])
			continue
		}

		decoded = append(decoded, byte(v))
		i += advance
	}

	return !utf8.Valid(decoded)
}
