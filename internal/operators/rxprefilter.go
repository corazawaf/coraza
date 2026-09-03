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
//     uses a Wu-Manber shift table to skip non-candidate positions in sub-linear
//     time, verifying only at positions where a match could begin.
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
	"slices"
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

	// Compute the minimum byte length any matching input must have.
	// We use this in two ways:
	//   1. Prepended to every prefilter as a free O(1) guard that rejects
	//      inputs shorter than the pattern's minimum match length before
	//      spending O(H) on a string scan.
	//   2. As a standalone prefilter when extractLiterals returns nil but
	//      the minimum length is large enough to be useful (≥ minUsefulMML).
	//
	// re is already parsed and simplified above — call minLen directly to
	// avoid a second syntax.Parse + Simplify call on the same pattern.
	mml := minLen(re)

	lits := extractLiterals(re, caseInsensitive)
	if lits == nil {
		// No literals extractable. Fall back to a length-only prefilter when
		// the minimum match length is large enough to actually reject inputs.
		// Most WAF field values are > 3 bytes, so thresholds below 4 are not
		// worth the function-call overhead.
		const minUsefulMML = 4
		if mml >= minUsefulMML {
			return func(s string) bool { return len(s) >= mml }
		}
		return nil
	}

	var pf func(string) bool

	switch v := lits.(type) {
	case allRequired:
		// allRequired: every literal must be present in the input.
		// Example: pattern "hello.*world" yields allRequired{"hello", "world"}.
		//
		// Gap 1: when the pattern is start/end-anchored, the first/last literal
		// must appear at position 0/end — use HasPrefix/HasSuffix instead of
		// Contains for a faster O(k) check that also raises the reject rate.
		//
		// Gap 3: for non-anchored patterns, sort longest-first so the most
		// selective literal is checked first, maximising early exit.

		// Save origFirst/origLast before filterShort mutates the slice in-place.
		origFirst := ""
		if len(v) > 0 {
			origFirst = v[0]
		}
		origLast := ""
		if len(v) > 0 {
			origLast = v[len(v)-1]
		}
		filtered := filterShort(v, 2)
		if len(filtered) == 0 {
			return nil
		}
		// A literal is the prefix/suffix constraint only when it survived
		// filterShort (len >= 2), meaning it IS the first/last literal in the
		// pattern and not replaced by a longer one that appeared elsewhere.
		usePrefix := hasBeginAnchor(re) && len(origFirst) >= 2
		useSuffix := hasEndAnchor(re) && len(origLast) >= 2
		if !usePrefix && !useSuffix {
			// No anchor: sort longest-first for best early exit.
			slices.SortFunc(filtered, func(a, b string) int { return len(b) - len(a) })
		}
		pf = buildMultiNeedlePF(filtered, caseInsensitive, usePrefix, useSuffix)

	case combinedRequired:
		// combinedRequired: both allRequired and anyRequired constraints must hold.
		// Check allRequired (Contains/HasPrefix) first, then anyRequired (indexedMatcher).
		pf = buildCombinedPF(v, caseInsensitive, re)

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
		case caseInsensitive && !allASCIIStrings([]string(filtered)):
			// Our matchers use ASCII-only folding. If any needle is non-ASCII,
			// it could fold to an ASCII equivalent under Go's Unicode case
			// rules — causing a false negative. Bail out.
			return nil
		case len(filtered) <= anyRequiredMaxN:
			// Wu-Manber shift-table matcher. Sub-linear scanning examines only
			// ~H/minLen positions on average. Zero allocations.
			// For large N (>16), the shift table fills up with more zeros, but
			// benchmarks show it still outperforms any AC library for typical
			// WAF inputs (50-2000 B) because AC SIMD prefilters call
			// bytes.IndexByte once per unique start byte — O(H×K) in practice.
			im := newIndexedMatcher(filtered, caseInsensitive)
			pf = im.match
		default:
			// N > anyRequiredMaxN: too many needles for Wu-Manber to be
			// effective (nearly every haystack byte is a candidate). In
			// practice regexp/syntax.Simplify() factors large alternations
			// into tries with single-byte literals at each branch, causing
			// extractLiterals to return nil before we ever reach this branch.
			// If we do reach it, bail out and let the full regex run —
			// correctness over performance.
			return nil
		}
	}

	if pf == nil {
		return nil
	}

	// Prepend a free O(1) length guard to the literal scan.  If the input
	// is shorter than the minimum possible match length it can't match —
	// reject immediately before spending O(H) on string searches.
	// Only bother when mml is large enough to ever fire in practice.
	const minUsefulMML = 4
	if mml >= minUsefulMML {
		inner := pf
		pf = func(s string) bool {
			return len(s) >= mml && inner(s)
		}
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

// combinedRequired means every literal in 'all' must be present in the input
// AND at least one literal in 'any' must be present. Both constraints are
// necessary conditions extracted from different parts of the same regex.
type combinedRequired struct {
	all allRequired
	any anyRequired
}

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
		// Collect required literals from every non-optional child.
		//
		// allRequired: every literal must appear → strongest constraint.
		// anyRequired: at least one of these must appear → weaker, but still
		//   a valid necessary condition because the child is not optional.
		//   OpQuest and OpStar children already return nil, so any anyRequired
		//   we see here came from a mandatory child of the concat.
		//
		// When multiple anyRequired sets are collected (e.g. two keyword
		// alternations), we keep the most restrictive one — the set with the
		// fewest elements — because it is the hardest for benign traffic to
		// satisfy and therefore gives the best skip rate.  Both are correct
		// (either one is a valid necessary condition); the shorter one is
		// simply a better prefilter.
		//
		// Example: (?:^|["':;=])\s*(?:select|union|drop)
		//   child 0: (?:^|["':;=])  → nil (^ branch makes whole alt nil)
		//   child 1: \s*             → nil (star)
		//   child 2: (?:select|…)   → anyRequired{"select","union","drop"}
		//   → return anyRequired{"select","union","drop"}
		var all []string
		var bestAny anyRequired
		for _, sub := range re.Sub {
			lits := extractLiterals(sub, ci)
			if lits == nil {
				continue
			}
			switch v := lits.(type) {
			case allRequired:
				all = append(all, v...)
			case anyRequired:
				if bestAny == nil || len(v) < len(bestAny) {
					bestAny = v
				}
			}
		}
		if len(all) > 0 {
			// Gap 4: when a mandatory child also contributes an anyRequired
			// constraint (e.g. `SELECT.*FROM.*(?:users|accounts)`), combining
			// both makes the prefilter strictly more selective.
			if bestAny != nil && !anyTooShort(bestAny, 2) {
				return combinedRequired{all: allRequired(all), any: bestAny}
			}
			return allRequired(all)
		}

		// Try trie reconstruction BEFORE falling back to the raw anyRequired
		// propagation. Trie reconstruction prepends the short common prefix to
		// each suffix, producing longer and more selective literals — e.g.
		//
		//   s(?:e(?:lect|t)|leep)  →  anyRequired{"select","set","sleep"}
		//
		// The anyRequired propagation alone would yield {"elect","et","leep"};
		// "et" is a substring of ordinary words ("GET", "better", …) and would
		// let far too much benign traffic through to the full regex.
		//
		// Try trie reconstruction for patterns that regexp/syntax.Simplify()
		// emits when factoring common prefixes out of large alternations:
		//
		//   select|sleep|substr  →  s(?:elect|leep|ubstr)
		//   union|update         →  u(?:nion|pdate)
		//
		// The AST is OpConcat([OpLiteral("s"), OpAlternate([...])]).
		// extractLiterals(OpLiteral("s")) returns nil (1 byte, too short), so
		// the standard path above produces nothing. We detect this pattern and
		// reconstruct the full words by prepending the raw prefix to each branch.
		//
		// This enables prefiltering for large CRS alternation patterns that the
		// standard path would silently skip.
		//
		// IMPORTANT: trieReconstruct returns a concrete anyRequired type. When
		// that nil concrete value is returned directly as interface{}, Go wraps
		// it as (type=anyRequired, value=nil), which is != nil as an interface.
		// The callers in OpAlternate check `if lits == nil` — they'd see the
		// non-nil interface and treat it as a valid (empty) result, silently
		// building a wrong prefilter. Explicitly return nil (the interface nil).
		if result := trieReconstruct(re, ci); result != nil {
			return result
		}

		// Last resort: fall back to the anyRequired collected from required
		// children. This handles patterns like:
		//   (?:^|["':;=])\s*(?:select|union|drop)
		// where (?:^|…) has no extractable literal (^ branch makes it nil)
		// but the keyword alternation does. We couldn't use it above because
		// trieReconstruct (which prepends a common prefix) takes priority and
		// might have been able to produce better literals — but it didn't, so
		// this is the best we can do.
		if bestAny != nil {
			return bestAny
		}
		return nil

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
			case combinedRequired:
				// combinedRequired means every element of .all AND at least one
				// element of .any must be present when this branch fires.
				// For the parent anyRequired we need at least one guaranteed literal
				// per branch. The .any elements satisfy exactly that — when this
				// branch fires, at least one of .any is guaranteed to be present.
				// Mirror the anyRequired case: merge all .any elements so no branch
				// representative is accidentally omitted.
				branchLits = append(branchLits, []string(v.any)...)
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

// trieReconstruct handles the specific pattern that regexp/syntax.Simplify()
// emits when factoring a common prefix from an alternation:
//
//	select|sleep|substr  →  s(?:elect|leep|ubstr)
//	    AST: OpConcat([OpLiteral("s"), OpAlternate([...])])
//
// It prepends the raw prefix literal to every element returned by
// rawExtractSuffixes, recovering the full literal words. The result is returned
// as anyRequired so the caller knows "at least one of these must be present".
//
// Handles arbitrary nesting depth: rawExtractSuffixes recurses back into
// extractLiterals → trieReconstruct for inner OpConcat nodes, so patterns like
//
//	select|set|sleep  →  s(?:e(?:lect|t)|leep)
//
// also reconstruct correctly ("select", "set", "sleep").
func trieReconstruct(concat *syntax.Regexp, ci bool) anyRequired {
	// Only handle the exact 2-child pattern [short_prefix, alternation] that
	// regexp/syntax.Simplify() emits. Longer concats (e.g. a.*b) have
	// intervening optional/unknown nodes that we must not skip over, as doing
	// so would produce false negatives (e.g. "ab" present without "axb" being
	// a valid match for a.*b).
	if concat.Op != syntax.OpConcat || len(concat.Sub) != 2 {
		return nil
	}

	// Extract the raw prefix literal (may be 1 byte — that's the common case).
	prefix := rawLiteral(concat.Sub[0], ci)
	if prefix == "" {
		return nil
	}

	// Collect suffix candidates from remaining children using the permissive
	// extractor that allows short literals (they will be combined with prefix).
	var suffixes []string
	for _, sub := range concat.Sub[1:] {
		lits := rawExtractSuffixes(sub, ci)
		if lits == nil {
			continue
		}
		suffixes = append(suffixes, lits...)
	}
	if len(suffixes) == 0 {
		return nil
	}

	result := make(anyRequired, 0, len(suffixes))
	for _, s := range suffixes {
		if full := prefix + s; len(full) >= 2 {
			result = append(result, full)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// rawExtractSuffixes extracts literal candidates from a regex subtree for use
// as trie-reconstruction suffixes. Unlike extractLiterals it permits short
// literals (< 2 bytes) because they will be combined with a prefix by the
// caller, producing a longer and more selective string.
//
// Returns nil if any branch of an alternation has no extractable literal (same
// semantics as extractLiterals for OpAlternate: we can't safely omit a branch).
func rawExtractSuffixes(re *syntax.Regexp, ci bool) []string {
	switch re.Op {
	case syntax.OpLiteral:
		s := rawLiteral(re, ci)
		if s == "" {
			return nil
		}
		return []string{s}

	case syntax.OpAlternate:
		var result []string
		for _, sub := range re.Sub {
			lits := rawExtractSuffixes(sub, ci)
			if lits == nil {
				return nil // one branch has no extractable suffix → bail
			}
			result = append(result, lits...)
		}
		return result

	case syntax.OpConcat:
		// Try the full extractLiterals pipeline first (handles deeper nesting
		// through the trieReconstruct fallback it already calls).
		lits := extractLiterals(re, ci)
		if lits != nil {
			switch v := lits.(type) {
			case allRequired:
				// Only safe to return a single trie suffix when the concat
				// collapses to exactly one contiguous literal. Multiple
				// allRequired elements mean there are wildcards between them
				// (e.g. "elect.*from" → allRequired{"elect","from"}). Joining
				// them would produce "electfrom" — a phantom string that never
				// appears contiguously in a real input — causing false negatives
				// on valid matches like "select x from". Return nil here so the
				// caller falls back to the safer anyRequired propagation instead.
				if len(v) == 1 {
					return []string{v[0]}
				}
				return nil
			case anyRequired:
				return []string(v)
			case combinedRequired:
				// For trie-reconstruction we need a suffix that is *always* present
				// when this sub-concat fires. The .all elements are guaranteed;
				// .any elements are only conditionally present (one of them must be
				// present, but not a specific one). Returning a .any element would
				// let the outer prefix combine with a wrong suffix (e.g. "s"+"execute"
				// instead of "s"+"p_"+"execute" → "sp_execute"), producing a phantom
				// literal that never appears contiguously in real input.
				// Return the single longest .all element as the guaranteed suffix.
				rep := longest([]string(v.all))
				if rep == "" {
					return nil
				}
				return []string{rep}
			}
		}
		return nil

	case syntax.OpCapture:
		return rawExtractSuffixes(re.Sub[0], ci)

	default:
		return nil
	}
}

// rawLiteral returns the string content of an OpLiteral node without applying
// any minimum-length filter. Returns "" if the node is not a valid literal.
// Used for trie reconstruction where short prefixes are intentionally combined
// with alternation branches to form longer, more selective literals.
func rawLiteral(re *syntax.Regexp, ci bool) string {
	if re.Op != syntax.OpLiteral {
		return ""
	}
	for _, r := range re.Rune {
		if r == utf8.RuneError {
			return ""
		}
	}
	s := string(re.Rune)
	if ci {
		s = strings.ToLower(s)
	}
	return s
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
//
// Compacts in place to avoid a heap allocation when all (or most) elements pass.
func filterShort(ss []string, minLen int) []string {
	k := 0
	for _, s := range ss {
		if len(s) >= minLen {
			ss[k] = s
			k++
		}
	}
	return ss[:k]
}

// anyRequiredMaxN is an upper bound on the number of needles we will build an
// indexedMatcher for. Beyond this count the Wu-Manber shift table fills up with
// zeros (every haystack byte is a candidate position), so the sub-linear skip
// degenerates — but even in the degenerate case the 256-byte table and small
// per-bucket cost beats any Aho-Corasick library for typical WAF inputs
// (50-2000 byte values), because AC SIMD prefilters call bytes.IndexByte once
// per unique start byte — O(H × K) when K (unique first bytes) is large.
//
// 256 covers even the largest CRS alternation sets seen in practice.
// Raise if profiling shows Wu-Manber still wins beyond that.
const anyRequiredMaxN = 256

// indexedMatcher performs sub-linear multi-pattern substring matching using a
// Wu-Manber style shift table. Instead of examining every byte in the haystack,
// it slides a window of size minLen and looks at the byte at the window's right
// edge. A precomputed shift table tells it how far to jump: if the byte doesn't
// appear near the end of any needle, the window can advance by up to minLen
// bytes at once. Only when the shift is zero (a potential match position) does
// it verify against the small set of candidate needles.
//
// Average case: O(H/minLen) — for typical CRS keywords (minLen ≈ 5-6), this
// examines only ~1/5 to ~1/6 of the haystack bytes, versus O(H) for the
// bitmap approach or Aho-Corasick.
//
// This beats Aho-Corasick for small pattern sets (N < ~20) because:
//   - Sub-linear scanning vs AC's strict O(H) single-pass
//   - Zero allocations (AC's Iter/Match pattern allocates per call)
//   - Better cache behavior (256-byte table vs large DFA transition table)
type indexedMatcher struct {
	shift      [256]uint8    // shift distance per byte value; 0 = candidate position
	endBuckets [256][]string // needles grouped by their byte at position minLen-1
	minLen     int
	ci         bool
}

func newIndexedMatcher(needles []string, ci bool) *indexedMatcher {
	if len(needles) == 0 {
		return &indexedMatcher{ci: ci, minLen: 0}
	}
	im := &indexedMatcher{ci: ci}

	im.minLen = len(needles[0])
	for _, n := range needles[1:] {
		if len(n) < im.minLen {
			im.minLen = len(n)
		}
	}

	ml := im.minLen
	if ml > 255 {
		ml = 255
	}
	for i := range im.shift {
		im.shift[i] = uint8(ml)
	}

	// Normalize needles to lowercase for CI mode.
	norms := needles
	if ci {
		norms = make([]string, len(needles))
		for i, n := range needles {
			norms[i] = strings.ToLower(n)
		}
	}

	for _, n := range norms {
		for j := 0; j < im.minLen; j++ {
			sh := uint8(im.minLen - 1 - j)
			c := n[j]
			if sh < im.shift[c] {
				im.shift[c] = sh
			}
			if ci && c >= 'a' && c <= 'z' {
				upper := c - ('a' - 'A')
				if sh < im.shift[upper] {
					im.shift[upper] = sh
				}
			}
		}
	}

	for _, n := range norms {
		c := n[im.minLen-1]
		im.endBuckets[c] = append(im.endBuckets[c], n)
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
	ml := m.minLen
	if ml == 0 || len(s) < ml {
		return false
	}
	i := ml - 1
	for i < len(s) {
		sh := m.shift[s[i]]
		if sh != 0 {
			i += int(sh)
			continue
		}
		pos := i - ml + 1
		for _, needle := range m.endBuckets[s[i]] {
			nlen := len(needle)
			if pos+nlen <= len(s) && s[pos:pos+nlen] == needle {
				return true
			}
		}
		i++
	}
	return false
}

func (m *indexedMatcher) matchCI(s string) bool {
	ml := m.minLen
	if ml == 0 || len(s) < ml {
		return false
	}
	i := ml - 1
	for i < len(s) {
		b := s[i]
		sh := m.shift[b]
		if sh != 0 {
			i += int(sh)
			continue
		}
		lb := b
		if lb >= 'A' && lb <= 'Z' {
			lb += 'a' - 'A'
		}
		pos := i - ml + 1
		for _, needle := range m.endBuckets[lb] {
			nlen := len(needle)
			if pos+nlen <= len(s) && equalFoldASCIIBytes(s[pos:pos+nlen], needle) {
				return true
			}
		}
		i++
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

// containsFoldASCIIOnly is a case-insensitive substring search for ASCII-only
// needles. needle must already be lowercase.
//
// It uses strings.IndexByte — which the Go runtime maps to a SIMD instruction
// on amd64/arm64 — to jump straight to candidate positions (bytes that match
// the first byte of the needle in either case), then verifies the full needle
// at those positions. This is significantly faster than a byte-by-byte loop
// for typical WAF haystack sizes (50–2000 bytes).
func containsFoldASCIIOnly(s, needle string) bool {
	nlen := len(needle)
	limit := len(s) - nlen
	if limit < 0 {
		return false
	}

	first := needle[0] // already lowercase
	var upper byte
	hasUpper := first >= 'a' && first <= 'z'
	if hasUpper {
		upper = first - ('a' - 'A')
	}

	for i := 0; i <= limit; {
		// strings.IndexByte is accelerated by the Go runtime (SIMD on
		// amd64/arm64, scalar elsewhere) and is correct on every platform.
		lo := strings.IndexByte(s[i:], first)
		if hasUpper {
			hi := strings.IndexByte(s[i:], upper)
			if hi >= 0 && (lo < 0 || hi < lo) {
				lo = hi
			}
		}
		if lo < 0 {
			return false
		}
		i += lo
		if i > limit {
			return false
		}
		if equalFoldASCIIBytes(s[i:i+nlen], needle) {
			return true
		}
		i++
	}
	return false
}

// ---------------------------------------------------------------------------
// Anchor helpers (Gap 1)
// ---------------------------------------------------------------------------

// hasBeginAnchor reports whether re requires the match to start at position 0
// of the input. Only OpBeginText (\A) is accepted — OpBeginLine (^ with (?m))
// can match after any newline and is NOT a position-0 guarantee, so using
// strings.HasPrefix for it would produce false negatives on multi-line inputs.
func hasBeginAnchor(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpBeginText:
		return true
	case syntax.OpCapture:
		return hasBeginAnchor(re.Sub[0])
	case syntax.OpConcat:
		if len(re.Sub) > 0 {
			return hasBeginAnchor(re.Sub[0])
		}
	}
	return false
}

// hasEndAnchor reports whether re requires the match to end at the very last
// byte of the input. Only OpEndText (\z) is accepted for the same reason as
// hasBeginAnchor — OpEndLine ($ with (?m)) can match before any newline.
func hasEndAnchor(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpEndText:
		return true
	case syntax.OpCapture:
		return hasEndAnchor(re.Sub[0])
	case syntax.OpConcat:
		if len(re.Sub) > 0 {
			return hasEndAnchor(re.Sub[len(re.Sub)-1])
		}
	}
	return false
}

// hasPrefixFoldASCII reports whether s begins with prefix (ASCII case-insensitive).
// prefix must already be lowercase.
func hasPrefixFoldASCII(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return equalFoldASCIIBytes(s[:len(prefix)], prefix)
}

// hasSuffixFoldASCII reports whether s ends with suffix (ASCII case-insensitive).
// suffix must already be lowercase.
func hasSuffixFoldASCII(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return equalFoldASCIIBytes(s[len(s)-len(suffix):], suffix)
}

// buildMultiNeedlePF builds a prefilter function for an ordered set of needles.
// needles must already be lowercase when ci is true.
//
// usePrefix: needles[0] must appear at position 0 (pattern is start-anchored).
// useSuffix: needles[last] must appear at the very end of the input.
//
// When neither anchor is set, the caller should sort needles longest-first
// before calling so the most selective literal is checked first.
func buildMultiNeedlePF(needles []string, ci, usePrefix, useSuffix bool) func(string) bool {
	if len(needles) == 0 {
		return nil
	}

	// Partition into prefix, middle, and suffix segments.
	var prefix, suffix string
	middle := needles

	switch {
	case usePrefix && useSuffix && len(needles) >= 2:
		prefix = needles[0]
		suffix = needles[len(needles)-1]
		middle = needles[1 : len(needles)-1]
	case usePrefix && useSuffix:
		// Single needle: only prefix check (exact-match is handled by Gap 2).
		prefix = needles[0]
		middle = nil
	case usePrefix:
		prefix = needles[0]
		middle = needles[1:]
	case useSuffix:
		suffix = needles[len(needles)-1]
		middle = needles[:len(needles)-1]
	}

	if ci {
		return func(s string) bool {
			if prefix != "" && !hasPrefixFoldASCII(s, prefix) {
				return false
			}
			if suffix != "" && !hasSuffixFoldASCII(s, suffix) {
				return false
			}
			for _, needle := range middle {
				if !containsFoldASCII(s, needle) {
					return false
				}
			}
			return true
		}
	}
	return func(s string) bool {
		if prefix != "" && !strings.HasPrefix(s, prefix) {
			return false
		}
		if suffix != "" && !strings.HasSuffix(s, suffix) {
			return false
		}
		for _, needle := range middle {
			if !strings.Contains(s, needle) {
				return false
			}
		}
		return true
	}
}

// buildCombinedPF builds a prefilter that enforces both allRequired and
// anyRequired constraints. Both are necessary conditions; combining them
// produces a strictly more selective check.
//
// The outer prefilterFunc wrappers (MML guard, CI isASCII guard) are applied
// after this function returns — do NOT add them here.
func buildCombinedPF(v combinedRequired, ci bool, re *syntax.Regexp) func(string) bool {
	// Build allRequired part.
	allSlice := []string(v.all)
	origFirst := ""
	if len(allSlice) > 0 {
		origFirst = allSlice[0]
	}
	origLast := ""
	if len(allSlice) > 0 {
		origLast = allSlice[len(allSlice)-1]
	}
	filteredAll := filterShort(allSlice, 2)

	var allPF func(string) bool
	if len(filteredAll) > 0 {
		usePrefix := hasBeginAnchor(re) && len(origFirst) >= 2
		useSuffix := hasEndAnchor(re) && len(origLast) >= 2
		if !usePrefix && !useSuffix {
			slices.SortFunc(filteredAll, func(a, b string) int { return len(b) - len(a) })
		}
		allPF = buildMultiNeedlePF(filteredAll, ci, usePrefix, useSuffix)
	}

	// Build anyRequired part (same logic as the anyRequired case in prefilterFunc).
	filteredAny := v.any
	if ci && !allASCIIStrings([]string(filteredAny)) {
		// Non-ASCII needles in CI mode: unsafe, fall back to allRequired only.
		return allPF
	}

	var anyPF func(string) bool
	switch {
	case len(filteredAny) == 1:
		needle := filteredAny[0]
		if ci {
			anyPF = func(s string) bool { return containsFoldASCII(s, needle) }
		} else {
			anyPF = func(s string) bool { return strings.Contains(s, needle) }
		}
	case len(filteredAny) <= anyRequiredMaxN:
		im := newIndexedMatcher(filteredAny, ci)
		anyPF = im.match
	default:
		// Too many needles: use allRequired only.
		return allPF
	}

	if allPF == nil {
		return anyPF
	}
	outerPF := allPF
	return func(s string) bool { return outerPF(s) && anyPF(s) }
}

// ---------------------------------------------------------------------------
// Exact-match extraction (Gap 2, used by rx.go)
// ---------------------------------------------------------------------------

// extractExactMatch reports whether re is a pure literal equality check of the
// form ^literal$ (or \Aliteral\z, or (?i)^literal$). Returns the literal and
// whether matching is case-insensitive.
//
// Only OpBeginText (\A) and OpEndText (\z) are accepted. OpBeginLine and
// OpEndLine (^ and $ under (?m)) are NOT — the caller is expected to have
// parsed the original rule pattern without the (?m) flag (i.e. options.Arguments,
// not the (?sm)-wrapped data string from newRX).
func extractExactMatch(re *syntax.Regexp) (lit string, ci bool) {
	// Unwrap outer captures that regexp/syntax sometimes emits.
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	if re.Op != syntax.OpConcat || len(re.Sub) != 3 {
		return "", false
	}
	begin, middle, end := re.Sub[0], re.Sub[1], re.Sub[2]
	if begin.Op != syntax.OpBeginText || end.Op != syntax.OpEndText {
		return "", false
	}
	if middle.Op != syntax.OpLiteral {
		return "", false
	}
	for _, r := range middle.Rune {
		if r == utf8.RuneError {
			return "", false
		}
	}
	return string(middle.Rune), middle.Flags&syntax.FoldCase != 0
}
