// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.pm

package operators

import (
	"fmt"
	"strconv"
	"strings"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs case-insensitive pattern matching using the Aho-Corasick algorithm for efficient
// multi-pattern searching. Matches space-separated keywords or patterns provided as arguments.
//
// Arguments:
// Space-separated keywords or patterns to match. Supports Snort data syntax where raw bytes
// can be embedded using pipe-delimited hex notation, e.g. "A|42|C" or "|0d 0a|".
// All patterns are converted to lowercase for case-insensitive matching.
//
// Returns:
// true if any of the patterns are found in the input, false otherwise
//
// Example:
// ```
// # Detect known malicious user agents
// SecRule REQUEST_HEADERS:User-Agent "@pm WebZIP WebCopier Webster" "id:170,deny,log"
//
// # Match multiple attack patterns
// SecRule ARGS "@pm <script> javascript: onerror=" "id:171,deny"
//
// # Match using snort data syntax with hex bytes: A + 0x42('B') + C + 0x44('D') + F = "ABCDF"
// SecRule ARGS "@pm A|42|C|44|F" "id:172,deny"
// ```
type pm struct {
	matcher ahocorasick.AhoCorasick
}

var _ plugintypes.Operator = (*pm)(nil)

func newPM(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	dict, err := parsePMArgs(data)
	if err != nil {
		return nil, err
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	m, _ := memoizeDo(options.Memoizer, strings.ToLower(data), func() (any, error) { return builder.Build(dict), nil })
	return &pm{matcher: m.(ahocorasick.AhoCorasick)}, nil
}

// parsePMArgs parses the pm operator arguments, supporting Snort data syntax where raw bytes
// can be embedded using pipe-delimited hex notation. For example, "A|42|C" is parsed as the
// three-byte string "ABC" (since 0x42 = 'B'). Multiple hex bytes can be specified inside the
// pipes separated by spaces, e.g. "|0d 0a|" becomes a CRLF sequence.
//
// Patterns are separated by spaces that appear outside of pipe blocks.
func parsePMArgs(data string) ([]string, error) {
	var patterns []string
	var current strings.Builder
	var hexBuf strings.Builder
	inPipe := false

	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '|':
			if inPipe {
				// End of pipe block – flush any remaining hex token.
				if hexBuf.Len() > 0 {
					b, err := parseHexByte(hexBuf.String())
					if err != nil {
						return nil, err
					}
					current.WriteByte(b)
					hexBuf.Reset()
				}
				inPipe = false
			} else {
				inPipe = true
			}
		case inPipe && c == ' ':
			// Space inside a pipe block is a hex-byte separator.
			if hexBuf.Len() > 0 {
				b, err := parseHexByte(hexBuf.String())
				if err != nil {
					return nil, err
				}
				current.WriteByte(b)
				hexBuf.Reset()
			}
		case inPipe:
			hexBuf.WriteByte(c)
		case c == ' ':
			// Space outside a pipe block is a pattern separator.
			if current.Len() > 0 {
				patterns = append(patterns, strings.ToLower(current.String()))
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}

	if inPipe {
		return nil, fmt.Errorf("unclosed pipe in snort data syntax")
	}

	if current.Len() > 0 {
		patterns = append(patterns, strings.ToLower(current.String()))
	}

	return patterns, nil
}

// parseHexByte parses a one- or two-digit hexadecimal string into a byte.
func parseHexByte(s string) (byte, error) {
	b, err := strconv.ParseUint(strings.TrimSpace(s), 16, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid hex value %q in snort data syntax: %w", s, err)
	}
	return byte(b), nil
}

func (o *pm) Evaluate(tx plugintypes.TransactionState, value string) bool {
	return pmEvaluate(o.matcher, tx, value)
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
