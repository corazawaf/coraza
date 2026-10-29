// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.pm

package operators

import (
	"fmt"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs case-insensitive pattern matching using the Aho-Corasick algorithm for efficient
// multi-pattern searching. Matches space-separated keywords or patterns provided as arguments.
//
// Arguments:
// Space-separated keywords or patterns to match. Supports Snort data syntax like "A|42|C|44|F"
// for hex notation. Literal segments outside hex blocks are converted to lowercase. Hex blocks
// |...| decode byte-for-byte; spaces inside hex blocks are ignored, and literal pipes must be
// encoded as |7C|.
//
// Returns:
// true if any of the patterns are found in the input, false otherwise
//
// Example:
// ```seclang
// # Detect known malicious user agents
// SecRule REQUEST_HEADERS:User-Agent "@pm WebZIP WebCopier Webster" "id:170,deny,log"
//
// # Match multiple attack patterns
// SecRule ARGS "@pm <script> javascript: onerror=" "id:171,deny"
// ```
type pm struct {
	matcher ahocorasick.AhoCorasick
	// minLen is the length of the shortest pattern. If the input is shorter
	// than this, no pattern can match and we skip the Aho-Corasick automaton.
	minLen int
}

var _ plugintypes.Operator = (*pm)(nil)

func hexVal(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func parsePMPhrases(data string) ([]string, error) {
	var dict []string
	var current strings.Builder
	litStart := -1
	inHex := false
	blockStart := -1
	digitsInBlock := 0
	hasNibble := false
	var firstNibble byte

	for i := 0; i < len(data); i++ {
		b := data[i]
		if inHex {
			switch b {
			case '|':
				if digitsInBlock == 0 {
					return nil, fmt.Errorf("@pm: empty hex block at offset %d (use |7C| for literal pipe)", blockStart)
				}
				if hasNibble {
					return nil, fmt.Errorf("@pm: odd number of hex digits in block at offset %d", blockStart)
				}
				inHex = false
			case ' ':
				// Spaces inside hex blocks are ignored.
				continue
			default:
				val, ok := hexVal(b)
				if !ok {
					return nil, fmt.Errorf("@pm: invalid hex character %q at offset %d", b, i)
				}
				digitsInBlock++
				if !hasNibble {
					firstNibble = val
					hasNibble = true
				} else {
					current.WriteByte((firstNibble << 4) | val)
					hasNibble = false
				}
			}
		} else {
			switch b {
			case '|':
				if litStart != -1 {
					current.WriteString(strings.ToLower(data[litStart:i]))
					litStart = -1
				}
				inHex = true
				blockStart = i
				digitsInBlock = 0
				hasNibble = false
			case ' ':
				if litStart != -1 {
					current.WriteString(strings.ToLower(data[litStart:i]))
					litStart = -1
				}
				if current.Len() > 0 {
					dict = append(dict, current.String())
					current.Reset()
				}
			default:
				if litStart == -1 {
					litStart = i
				}
			}
		}
	}

	if inHex {
		return nil, fmt.Errorf("@pm: unclosed hex block at offset %d (use |7C| for literal pipe)", blockStart)
	}

	if litStart != -1 {
		current.WriteString(strings.ToLower(data[litStart:]))
	}

	if current.Len() > 0 {
		dict = append(dict, current.String())
	}

	if len(dict) == 0 {
		return nil, fmt.Errorf("@pm: empty operator pattern")
	}

	return dict, nil
}

func newPM(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	dict, err := parsePMPhrases(options.Arguments)
	if err != nil {
		return nil, err
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	m, err := memoizeDo(options.Memoizer, memoizeKey("pm", dict...), func() (any, error) {
		return builder.Build(dict), nil
	})
	if err != nil {
		return nil, err
	}

	return &pm{matcher: m.(ahocorasick.AhoCorasick), minLen: minPatternLen(dict)}, nil
}

func (o *pm) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if len(value) < o.minLen {
		return false
	}
	return pmEvaluate(o.matcher, tx, value)
}

// minPatternLen returns the length of the shortest pattern.
// If any pattern is empty it returns 0 immediately, disabling short-circuiting:
// an empty pattern matches every input, so no input can be safely skipped.
// If there are no patterns, it returns 0.
func minPatternLen(patterns []string) int {
	min := 0
	for _, p := range patterns {
		if len(p) == 0 {
			return 0
		}
		if min == 0 || len(p) < min {
			min = len(p)
		}
	}
	return min
}

func pmEvaluate(matcher ahocorasick.AhoCorasick, tx plugintypes.TransactionState, value string) bool {
	iter := matcher.Iter(value)

	if !tx.Capturing() {
		// Not capturing so just one match is enough.
		return iter.Next() != nil
	}

	var numMatches int
	for {
		m := iter.Next()
		if m == nil {
			break
		}

		tx.CaptureField(numMatches, value[m.Start():m.End()])

		numMatches++
		if numMatches == 10 {
			return true
		}
	}

	return numMatches > 0
}

func init() {
	Register("pm", newPM)
}
