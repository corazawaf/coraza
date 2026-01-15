// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"bytes"
	"strings"
	"testing"
)

// Boyer-Moore-Horspool implementation
type bmh struct {
	pattern    string
	badCharMap [256]int
}

func newBMH(pattern string) *bmh {
	b := &bmh{pattern: pattern}
	m := len(pattern)

	// Initialize bad character table
	for i := 0; i < 256; i++ {
		b.badCharMap[i] = m
	}

	// Fill bad character table
	for i := 0; i < m-1; i++ {
		b.badCharMap[pattern[i]] = m - 1 - i
	}

	return b
}

func (b *bmh) search(text string) bool {
	n := len(text)
	m := len(b.pattern)

	if m > n {
		return false
	}

	skip := 0
	for skip <= n-m {
		j := m - 1
		for j >= 0 && b.pattern[j] == text[skip+j] {
			j--
		}

		if j < 0 {
			return true
		}

		skip += b.badCharMap[text[skip+m-1]]
	}

	return false
}

// Naive brute force implementation
func naiveSearch(text, pattern string) bool {
	n := len(text)
	m := len(pattern)

	if m > n {
		return false
	}

	for i := 0; i <= n-m; i++ {
		j := 0
		for j < m && text[i+j] == pattern[j] {
			j++
		}
		if j == m {
			return true
		}
	}

	return false
}

// Test data generators
var (
	shortPattern = "WebZIP"
	longPattern  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

	shortText     = "User-Agent: WebZIP/7.0"
	mediumText    = "Mozilla/5.0 (compatible; WebZIP/7.0; Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	longText      = strings.Repeat("abcdefghij", 100) + "WebZIP" + strings.Repeat("klmnopqrst", 100)
	veryLongText  = strings.Repeat("x", 10000) + "WebZIP" + strings.Repeat("y", 10000)
	noMatchText   = strings.Repeat("abcdefghijklmnopqrstuvwxyz", 100)
)

// Benchmark strings.Contains (Rabin-Karp)
func BenchmarkStringsContains_ShortPattern_ShortText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Contains(shortText, shortPattern)
	}
}

func BenchmarkStringsContains_ShortPattern_MediumText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Contains(mediumText, shortPattern)
	}
}

func BenchmarkStringsContains_ShortPattern_LongText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Contains(longText, shortPattern)
	}
}

func BenchmarkStringsContains_ShortPattern_VeryLongText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Contains(veryLongText, shortPattern)
	}
}

func BenchmarkStringsContains_ShortPattern_NoMatch(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Contains(noMatchText, shortPattern)
	}
}

func BenchmarkStringsContains_LongPattern_LongText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Contains(longText, longPattern)
	}
}

// Benchmark strings.Index
func BenchmarkStringsIndex_ShortPattern_ShortText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Index(shortText, shortPattern) >= 0
	}
}

func BenchmarkStringsIndex_ShortPattern_MediumText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Index(mediumText, shortPattern) >= 0
	}
}

func BenchmarkStringsIndex_ShortPattern_LongText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Index(longText, shortPattern) >= 0
	}
}

func BenchmarkStringsIndex_ShortPattern_VeryLongText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = strings.Index(veryLongText, shortPattern) >= 0
	}
}

// Benchmark bytes.Contains
func BenchmarkBytesContains_ShortPattern_ShortText(b *testing.B) {
	textBytes := []byte(shortText)
	patternBytes := []byte(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bytes.Contains(textBytes, patternBytes)
	}
}

func BenchmarkBytesContains_ShortPattern_MediumText(b *testing.B) {
	textBytes := []byte(mediumText)
	patternBytes := []byte(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bytes.Contains(textBytes, patternBytes)
	}
}

func BenchmarkBytesContains_ShortPattern_LongText(b *testing.B) {
	textBytes := []byte(longText)
	patternBytes := []byte(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bytes.Contains(textBytes, patternBytes)
	}
}

func BenchmarkBytesContains_ShortPattern_VeryLongText(b *testing.B) {
	textBytes := []byte(veryLongText)
	patternBytes := []byte(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bytes.Contains(textBytes, patternBytes)
	}
}

// Benchmark Boyer-Moore-Horspool
func BenchmarkBMH_ShortPattern_ShortText(b *testing.B) {
	bmh := newBMH(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bmh.search(shortText)
	}
}

func BenchmarkBMH_ShortPattern_MediumText(b *testing.B) {
	bmh := newBMH(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bmh.search(mediumText)
	}
}

func BenchmarkBMH_ShortPattern_LongText(b *testing.B) {
	bmh := newBMH(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bmh.search(longText)
	}
}

func BenchmarkBMH_ShortPattern_VeryLongText(b *testing.B) {
	bmh := newBMH(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bmh.search(veryLongText)
	}
}

func BenchmarkBMH_ShortPattern_NoMatch(b *testing.B) {
	bmh := newBMH(shortPattern)
	for i := 0; i < b.N; i++ {
		_ = bmh.search(noMatchText)
	}
}

// Benchmark Naive brute force
func BenchmarkNaive_ShortPattern_ShortText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = naiveSearch(shortText, shortPattern)
	}
}

func BenchmarkNaive_ShortPattern_MediumText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = naiveSearch(mediumText, shortPattern)
	}
}

func BenchmarkNaive_ShortPattern_LongText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = naiveSearch(longText, shortPattern)
	}
}

func BenchmarkNaive_ShortPattern_VeryLongText(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = naiveSearch(veryLongText, shortPattern)
	}
}

// Verify all implementations produce the same results
func TestImplementationsMatch(t *testing.T) {
	bmh := newBMH(shortPattern)

	testCases := []struct {
		name     string
		text     string
		pattern  string
		expected bool
	}{
		{"short match", shortText, shortPattern, true},
		{"medium match", mediumText, shortPattern, true},
		{"long match", longText, shortPattern, true},
		{"very long match", veryLongText, shortPattern, true},
		{"no match", noMatchText, shortPattern, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result1 := strings.Contains(tc.text, tc.pattern)
			result2 := strings.Index(tc.text, tc.pattern) >= 0
			result3 := bytes.Contains([]byte(tc.text), []byte(tc.pattern))
			result4 := bmh.search(tc.text)
			result5 := naiveSearch(tc.text, tc.pattern)

			if result1 != tc.expected || result2 != tc.expected ||
			   result3 != tc.expected || result4 != tc.expected || result5 != tc.expected {
				t.Errorf("implementations disagree: strings.Contains=%v, strings.Index=%v, bytes.Contains=%v, BMH=%v, naive=%v, expected=%v",
					result1, result2, result3, result4, result5, tc.expected)
			}
		})
	}
}
