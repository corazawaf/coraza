// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// rxprefilter implements compile-time analysis of regex patterns to build cheap
// pre-checks that can skip expensive regexp.Regexp evaluation when the input
// clearly cannot match.
//
// Why this exists:
//
// CRS loads hundreds of @rx rules and each one is evaluated against every
// relevant variable value per request. For typical benign traffic, the vast majority of
// these evaluations return false. The regex engine still has to run in full
// before concluding "no match". This file provides two mechanisms to short-
// circuit that work:
//
//  1. Minimum match length — computed by walking the regexp/syntax AST. If the
//     input is shorter than the minimum number of bytes the pattern could ever
//     match, we skip the regex entirely.
//
//  2. Required literal pre-filtering — also extracted from the AST. Every regex
//     has certain literal substrings that *must* appear in any matching input.
//     For example, `sleep\s*\(` always requires "sleep" and "(". If we can
//     cheaply confirm those literals are absent, we know the regex cannot match
//     and skip it. For single literals we use strings.Contains; for alternation
//     sets (anyRequired) we use a first-byte indexed single-pass scan that
//     checks a 256-bit bitmap per byte and only verifies at candidate positions.
//
// Safety guarantee:
//
// The prefilter can only produce two outcomes:
//   - "definitely no match" → skip regex (correct: required literals absent)
//   - "maybe match" → run regex (conservative: may still not match)
//
// A bug in literal extraction can only make the prefilter say "maybe" too
// often (degraded performance), never cause a false negative (missed attack).
// This is safe by construction — the prefilter is a necessary-condition check,
// not a sufficient-condition check.
//
// Design principle: when in doubt, fall back to the regex. The prefilter is
// purely an optimization. If there is any uncertainty about whether the input
// could match (e.g., non-ASCII input with case-insensitive patterns, unknown
// AST nodes, unparseable patterns), we return "maybe match" and let the full
// regex engine make the final decision. A missed optimization is free; a missed
// attack is a security vulnerability.
//
// AST walk rules for literal extraction (extractLiterals):
//
//   - OpLiteral → the literal string itself (required)
//   - OpConcat  → collect required literals from all children
//   - OpAlternate → at least one branch must match, so we pick the best
//     literal from each branch and build an "any of these" check
//   - OpCapture / OpPlus / OpRepeat(min>=1) → recurse into sub-expression
//   - OpStar / OpQuest / OpRepeat(min==0) → skip (optional, no guarantee)
//   - When (?i) is set, literals are lowercased and compared case-insensitively
//
// AST walk rules for minimum length (minLen):
//
//   - OpLiteral → byte length of the runes
//   - OpConcat  → sum of children
//   - OpAlternate → minimum across children
//   - OpPlus → child minimum (at least one repetition)
//   - OpStar / OpQuest → 0
//   - OpRepeat → re.Min * child minimum
//   - OpCharClass / OpAnyChar → 1

package operators

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// minMatchLength computes the minimum number of bytes an input must have
// for the compiled regex to possibly match. Returns 0 when unknown.
func minMatchLength(pattern string) int {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return 0
	}
	re = re.Simplify()
	return minLen(re)
}

// minLen computes the minimum byte length a matching input must have for the
// given regex AST node. Returns 0 for unknown or optional nodes.
func minLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		// Count byte length per rune. U+FFFD (RuneError) is special: Go's
		// regexp engine matches it against a single invalid UTF-8 byte (1 byte),
		// but its UTF-8 encoding is 3 bytes. Count it as 1 to avoid rejecting
		// inputs that the regex would actually match.
		n := 0
		for _, r := range re.Rune {
			if r == utf8.RuneError {
				n++
			} else {
				n += utf8.RuneLen(r)
			}
		}
		return n
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar, syntax.OpCharClass:
		// Any single character match requires at least 1 byte.
		return 1
	case syntax.OpCapture:
		// Capture groups don't add length, just recurse into the content.
		return minLen(re.Sub[0])
	case syntax.OpConcat:
		// All parts of a concatenation must match, so sum their minimums.
		n := 0
		for _, sub := range re.Sub {
			n += minLen(sub)
		}
		return n
	case syntax.OpAlternate:
		// Only one branch needs to match, so take the shortest branch.
		// Defensive: syntax.Parse never produces an empty OpAlternate after Simplify,
		// but guard anyway to avoid an index-out-of-bounds panic.
		if len(re.Sub) == 0 {
			return 0
		}
		m := minLen(re.Sub[0])
		for _, sub := range re.Sub[1:] {
			if v := minLen(sub); v < m {
				m = v
			}
		}
		return m
	case syntax.OpQuest, syntax.OpStar:
		// ? and * can match zero repetitions.
		return 0
	case syntax.OpPlus:
		// + requires at least one repetition.
		return minLen(re.Sub[0])
	case syntax.OpRepeat:
		// {n,m} requires at least n repetitions.
		// Note: syntax.Regexp.Simplify() expands counted repetitions into
		// OpConcat/OpQuest nodes, so this case is unreachable when minLen
		// is called after Simplify(). Kept as a correct fallback.
		if re.Min == 0 {
			return 0
		}
		return re.Min * minLen(re.Sub[0])
	default:
		// Unknown ops (e.g. OpBeginLine, OpEndLine) don't consume input.
		return 0
	}
}

// prefilterFunc returns a function that returns true if the regex might match
// the input, false if it definitely cannot. Returns nil when no useful
// prefilter can be built.
func prefilterFunc(pattern string) func(string) bool {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()

	caseInsensitive := hasFlag(re, syntax.FoldCase)

	lits := extractLiterals(re, caseInsensitive)
	if lits == nil {
		return nil
	}

	var pf func(string) bool

	switch v := lits.(type) {
	case allRequired:
		// allRequired: every literal must be present in the input.
		// Example: pattern "hello.*world" yields allRequired{"hello", "world"}.
		// We check each with strings.Contains; if any is absent, regex can't match.
		filtered := filterShort(v, 2)
		if len(filtered) == 0 {
			return nil
		}
		switch {
		case len(filtered) == 1:
			needle := filtered[0]
			if caseInsensitive {
				pf = func(s string) bool {
					return containsFoldASCII(s, needle)
				}
			} else {
				pf = func(s string) bool {
					return strings.Contains(s, needle)
				}
			}
		case caseInsensitive:
			pf = func(s string) bool {
				for _, needle := range filtered {
					if !containsFoldASCII(s, needle) {
						return false
					}
				}
				return true
			}
		default:
			pf = func(s string) bool {
				for _, needle := range filtered {
					if !strings.Contains(s, needle) {
						return false
					}
				}
				return true
			}
		}
	case anyRequired:
		// anyRequired: at least one literal must be present in the input.
		// Example: pattern "(?:union|insert)" yields anyRequired{"union", "insert"}.
		//
		// SAFETY: Do NOT use filterShort here. For anyRequired, removing a short
		// element changes the semantics from "one of {A,B,C}" to "one of {A,B}" —
		// if the match was through branch C (removed), we'd miss it. Instead, if
		// any element is too short to be useful, abandon the prefilter entirely.
		if anyTooShort(v, 2) {
			return nil
		}
		filtered := v
		switch {
		case len(filtered) == 1:
			needle := filtered[0]
			if caseInsensitive {
				pf = func(s string) bool {
					return containsFoldASCII(s, needle)
				}
			} else {
				pf = func(s string) bool {
					return strings.Contains(s, needle)
				}
			}
		} else if caseInsensitive && !allASCIIStrings([]string(filtered)) {
			// Our indexed matcher uses ASCII-only folding. If any needle is
			// non-ASCII, it could fold to an ASCII equivalent under Go's Unicode
			// case rules — causing a false negative. Bail out.
			return nil
		} else {
			im := newIndexedMatcher(filtered, caseInsensitive)
			pf = im.match
		}
	}

	if pf == nil {
		return nil
	}

	// When case-insensitive matching is active, our prefilter only performs
	// ASCII case folding (A-Z ↔ a-z). Go's regexp with (?i) uses full Unicode
	// simple case folding, where two ASCII letters have non-ASCII equivalents:
	//   - 's' ↔ 'ſ' (U+017F, Latin Small Letter Long S)
	//   - 'k' ↔ 'K' (U+212A, Kelvin Sign)
	// For pure-ASCII inputs this is not an issue — ASCII folding is complete.
	// For inputs containing non-ASCII bytes, we conservatively return true
	// ("maybe match") and let the full regex engine decide. This ensures we
	// never produce a false negative from Unicode folding mismatches.
	// In practice, 99%+ of WAF traffic is ASCII, so this rarely triggers.
	if caseInsensitive {
		inner := pf
		return func(s string) bool {
			if !isASCII(s) {
				return true
			}
			return inner(s)
		}
	}

	return pf
}

// literal extraction types

// allRequired means every string in the slice must appear in the input.
type allRequired []string

// anyRequired means at least one string in the slice must appear in the input.
type anyRequired []string

// extractLiterals walks the regex AST and returns the required literal substrings
// that must appear in any input for the regex to match. Returns:
//   - allRequired: every literal must be present (from concatenation)
//   - anyRequired: at least one literal must be present (from alternation)
//   - nil: no useful literals could be extracted
//
// The ci parameter controls case-insensitive mode: when true, extracted
// literals are lowercased so the caller can compare case-insensitively.
func extractLiterals(re *syntax.Regexp, ci bool) interface{} {
	switch re.Op {
	case syntax.OpLiteral:
		// U+FFFD in a literal matches single invalid UTF-8 bytes in Go's regexp,
		// but strings.Contains searches for the 3-byte encoding. Bail out to
		// avoid false negatives.
		for _, r := range re.Rune {
			if r == utf8.RuneError {
				return nil
			}
		}
		s := string(re.Rune)
		if ci {
			s = strings.ToLower(s)
		}
		// Single-byte literals are too common and not selective enough to filter on.
		if len(s) < 2 {
			return nil
		}
		return allRequired{s}

	case syntax.OpCapture:
		// Capture groups are transparent for literal extraction.
		return extractLiterals(re.Sub[0], ci)

	case syntax.OpConcat:
		var all []string
		for _, sub := range re.Sub {
			lits := extractLiterals(sub, ci)
			if lits == nil {
				continue
			}
			switch v := lits.(type) {
			case allRequired:
				all = append(all, v...)
			case anyRequired:
				// An anyRequired child means "one of these must exist" but we
				// can't promote any single element to allRequired. Skip it to
				// avoid false negatives.
				_ = v
			}
		}
		if len(all) == 0 {
			return nil
		}
		return allRequired(all)

	case syntax.OpAlternate:
		// For alternation (a|b|c), exactly one branch must match. So we need
		// at least one branch's required literal to be present in the input.
		// From each branch we pick its longest literal as the representative.
		// If any branch has no extractable literal, we can't pre-filter at all
		// because that branch could match without any of our literals.
		var branchLits []string
		for _, sub := range re.Sub {
			lits := extractLiterals(sub, ci)
			if lits == nil {
				// One branch has no extractable literal → can't pre-filter
				return nil
			}
			switch v := lits.(type) {
			case allRequired:
				// Pick the longest literal from this branch as its representative.
				branchLits = append(branchLits, longest(v))
			case anyRequired:
				// A nested alternation: any of its elements could satisfy this
				// branch. Merge all into the parent anyRequired — we can't pick
				// just one without risking false negatives.
				// Example: pattern `10|(10|00)` — branch B is anyRequired{"10","00"},
				// if we only kept "10" we'd miss input "00".
				branchLits = append(branchLits, v...)
			}
		}
		if len(branchLits) == 0 {
			return nil
		}
		return anyRequired(branchLits)

	case syntax.OpPlus:
		return extractLiterals(re.Sub[0], ci)

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return extractLiterals(re.Sub[0], ci)
		}
		return nil

	case syntax.OpQuest, syntax.OpStar:
		return nil

	default:
		return nil
	}
}

// hasFlag reports whether the flag is set on any node in the regex tree.
// Flags in Go's regexp/syntax can be scoped to sub-expressions (e.g. (?i:...)),
// so a top-level-only check would miss flags applied further down the tree.
func hasFlag(re *syntax.Regexp, flag syntax.Flags) bool {
	if re.Flags&flag != 0 {
		return true
	}
	for _, sub := range re.Sub {
		if hasFlag(sub, flag) {
			return true
		}
	}
	return false
}

// longest returns the longest string in ss, or "" if ss is empty.
func longest(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	best := ss[0]
	for _, s := range ss[1:] {
		if len(s) > len(best) {
			best = s
		}
	}
	return best
}

// anyTooShort returns true if any string in ss is shorter than minLen bytes.
// Used for anyRequired: if any alternative is too short, we can't safely filter
// because removing it would change "one of {A,B,C}" to "one of {A,B}" semantics.
func anyTooShort(ss []string, minLen int) bool {
	for _, s := range ss {
		if len(s) < minLen {
			return true
		}
	}
	return false
}

// filterShort removes strings shorter than minLen bytes. Very short literals
// (e.g. single characters) are too common across inputs to be effective filters.
// SAFETY: Only safe for allRequired (removing a needle makes the check less strict).
// Never use for anyRequired — use anyTooShort instead.
func filterShort(ss []string, minLen int) []string {
	result := ss[:0:0]
	for _, s := range ss {
		if len(s) >= minLen {
			result = append(result, s)
		}
	}
	return result
}

// indexedMatcher performs single-pass multi-pattern substring matching using a
// 256-bit first-byte bitmap and bucket-grouped verification. For each byte in
// the haystack, a single bit-test determines whether it could be the start of
// any needle. Only at candidate positions (~15% of bytes for typical CRS
// keywords) does it verify against the 1-3 needles sharing that first byte.
//
// This beats Aho-Corasick for small pattern sets (N < ~20) because:
//   - Per-byte cost is a single bit-test (register-local) vs DFA state
//     transition (indirect memory lookup into a multi-KB table)
//   - Single pass through the haystack (like AC) with early exit on first match
//   - Zero allocations (AC's Iter/Match pattern allocates per call)
//   - Better cache behavior (32-byte bitmap vs large DFA transition table)
type indexedMatcher struct {
	bitmap  [4]uint64    // 256-bit: which byte values start any needle
	buckets [256][]string // needles grouped by first byte
	minLen  int          // shortest needle length
	ci      bool         // case-insensitive mode
}

func newIndexedMatcher(needles []string, ci bool) *indexedMatcher {
	im := &indexedMatcher{ci: ci, minLen: len(needles[0])}
	for _, n := range needles {
		if len(n) < im.minLen {
			im.minLen = len(n)
		}
		b := n[0]
		im.bitmap[b>>6] |= 1 << (b & 63)
		if ci {
			// For CI matching, also set the uppercase variant so we catch both.
			if b >= 'a' && b <= 'z' {
				upper := b - ('a' - 'A')
				im.bitmap[upper>>6] |= 1 << (upper & 63)
			}
		}
		im.buckets[b] = append(im.buckets[b], n)
	}
	return im
}

func (m *indexedMatcher) match(s string) bool {
	if m.ci {
		return m.matchCI(s)
	}
	return m.matchCS(s)
}

func (m *indexedMatcher) matchCS(s string) bool {
	end := len(s) - m.minLen + 1
	for i := 0; i < end; i++ {
		b := s[i]
		if m.bitmap[b>>6]&(1<<(b&63)) == 0 {
			continue
		}
		for _, needle := range m.buckets[b] {
			nlen := len(needle)
			if i+nlen <= len(s) && s[i:i+nlen] == needle {
				return true
			}
		}
	}
	return false
}

func (m *indexedMatcher) matchCI(s string) bool {
	end := len(s) - m.minLen + 1
	for i := 0; i < end; i++ {
		b := s[i]
		if m.bitmap[b>>6]&(1<<(b&63)) == 0 {
			continue
		}
		lb := b
		if lb >= 'A' && lb <= 'Z' {
			lb += 'a' - 'A'
		}
		for _, needle := range m.buckets[lb] {
			nlen := len(needle)
			if i+nlen <= len(s) && equalFoldASCIIBytes(s[i:i+nlen], needle) {
				return true
			}
		}
	}
	return false
}

// equalFoldASCIIBytes compares two equal-length strings case-insensitively
// (ASCII only). The second argument (b) must already be lowercase.
func equalFoldASCIIBytes(a, b string) bool {
	for i := 0; i < len(a); i++ {
		ac := a[i]
		if ac >= 'A' && ac <= 'Z' {
			ac += 'a' - 'A'
		}
		if ac != b[i] {
			return false
		}
	}
	return true
}

// containsFoldASCII does a case-insensitive substring check.
// needle must already be lowercase.
func containsFoldASCII(s, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(s) < len(needle) {
		return false
	}
	// Fast path: check if all needle bytes are ASCII for simpler comparison.
	if isASCII(needle) {
		return containsFoldASCIIOnly(s, needle)
	}
	// For non-ASCII needles, strings.ToLower does not implement the same
	// Unicode folding rules as regexp/syntax.FoldCase (e.g., Greek sigma has
	// multiple fold equivalents). To preserve correctness, we conservatively
	// return true ("maybe match") and let the full regex decide.
	return true
}

// isASCII reports whether s contains only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func allASCIIStrings(ss []string) bool {
	for _, s := range ss {
		if !isASCII(s) {
			return false
		}
	}
	return true
}

// containsFoldASCIIOnly is a brute-force case-insensitive substring search
// optimized for ASCII-only needles. It lowercases each byte of s inline
// (only A-Z → a-z) and compares against needle which must already be lowercase.
// This avoids allocating a lowercased copy of s.
func containsFoldASCIIOnly(s, needle string) bool {
	nlen := len(needle)
	end := len(s) - nlen + 1
outer:
	for i := 0; i < end; i++ {
		for j := 0; j < nlen; j++ {
			sc := s[i+j]
			// Lowercase ASCII uppercase letters inline.
			if sc >= 'A' && sc <= 'Z' {
				sc += 'a' - 'A'
			}
			if sc != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}
