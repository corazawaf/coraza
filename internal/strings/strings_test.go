// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo
// +build !tinygo

package strings

import (
	"strings"
	"testing"
)

func TestMaybeRemoveQuotes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: ``,
			want:  ``,
		},
		{
			input: `"`,
			want:  `"`,
		},
		{
			input: `""`,
			want:  ``,
		},
		{
			input: `"hello world"`,
			want:  `hello world`,
		},
		{
			input: `'hello world'`,
			want:  `hello world`,
		},
		{
			input: `'hello "world'`,
			want:  `hello "world`,
		},
		{
			input: `'hello \'world'`,
			want:  `hello \'world`,
		},
		{
			input: `"hello 'world"`,
			want:  `hello 'world`,
		},
		{
			input: `"hello \"world"`,
			want:  `hello \"world`,
		},
		{
			input: `"hello world'`,
			want:  `"hello world'`,
		},
		{
			input: `"hello world`,
			want:  `"hello world`,
		},
		{
			input: `'hello world"`,
			want:  `'hello world"`,
		},
		{
			input: `'hello world`,
			want:  `'hello world`,
		},
		{
			input: `"\x{30cf}\x{30ed}\x{30fc} world"`,
			want:  `\x{30cf}\x{30ed}\x{30fc} world`,
		},
		{
			input: `"\s\x5c.*"`,
			want:  `\s\x5c.*`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := MaybeRemoveQuotes(tt.input); got != tt.want {
				t.Errorf("MaybeRemoveQuotes() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRandomStringConcurrency(t *testing.T) {
	// Make sure random strings don't crash under high concurrency.
	for i := 0; i < 5000; i++ {
		go RandomString(10000)
	}
}

func TestAsciiToLower(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Standard Uppercase", "HELLO WORLD", "hello world"},                // Standard uppercase input
		{"Already Lowercase", "hello world", "hello world"},                 // Already lowercase
		{"No Letters to Convert", "1234!@#$", "1234!@#$"},                   // Non-alphabetic characters
		{"Mixed Case", "GoLang", "golang"},                                  // Mixed case
		{"Leading and Trailing Spaces", "    SPACES    ", "    spaces    "}, // Leading/trailing spaces
		{"Unicode Unchanged", "Привет Мир", "Привет Мир"},                   // Unicode characters remain unchanged
		{"Mixed with Emojis", "😀😃😄😁🤣 Emoji TEST", "😀😃😄😁🤣 emoji test"},       // Emojis with mixed case text
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := AsciiToLower(test.input); got != test.expected {
				t.Errorf("AsciiToLower(%q) = %q; want %q", test.input, got, test.expected)
			}
		})
	}
}

func BenchmarkAsciiVsUnicodeCaseString(b *testing.B) {
	benchmarkCases := []struct {
		name string
		str  string
	}{
		{"ASCII Fully Lowercase Sentence", "this is a completely lowercase sentence for testing purposes."},
		{"ASCII Fully Uppercase Sentence", "THIS IS A COMPLETELY UPPERCASE SENTENCE FOR TESTING PURPOSES."},
		{"ASCII Mixed Case Sentence", "This Is A Randomized Mixed Case Sentence For Evaluation."},
		{"ASCII Non-Alphabetic Characters", "@@@@@@@ this text contains non-alphabetic symbols."},

		// Adding Unicode cases
		{"Unicode Greek Alphabet", "Αυτό είναι ένα τεστ με ελληνικούς χαρακτήρες."},
		{"Unicode Cyrillic Alphabet", "Это тест с использованием кириллических символов."},
		{"Unicode Mixed Greek and ASCII", "This is a mixed sentence: Ελληνικά και English."},
		{"Unicode Emoji", "😀😃😄😁🤣 Emoji characters mixed with text."},

		// Edge cases
		{"Empty String", ""},
		{"Only Punctuation", "!!!???...,,,"},
		{"Only Whitespace", "         "},
		{"Long Mixed Case String", "This is a really long sentence that is going to be used to test how the various implementations handle longer strings with a mix of cases. This should include UPPERCASE, lowercase, and a variety of symbols like $%^&*."},
		{"Special Turkish Case", "Turkish İ and i cases: İSTANBUL, istanbul, İstanbul, ıstanbul."},
	}

	// Benchmarking AsciiToLower function
	b.Run("AsciiToLower Implementation", func(b *testing.B) {
		for _, benchmarkCase := range benchmarkCases {
			b.Run(benchmarkCase.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_ = AsciiToLower(benchmarkCase.str)
				}
			})
		}
	})

	// Benchmarking a manual ASCII conversion method
	b.Run("Manual ASCII Conversion", func(b *testing.B) {
		for _, benchmarkCase := range benchmarkCases {
			b.Run(benchmarkCase.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					byteSlice := []byte(benchmarkCase.str)
					for j := 0; j < len(byteSlice); j++ {
						if byteSlice[j] >= 'A' && byteSlice[j] <= 'Z' {
							byteSlice[j] += 'a' - 'A'
						}
					}
					_ = string(byteSlice) // Convert byte slice back to string
				}
			})
		}
	})

	// Benchmarking standard Unicode case conversion
	b.Run("Standard Unicode ToLower", func(b *testing.B) {
		for _, benchmarkCase := range benchmarkCases {
			b.Run(benchmarkCase.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_ = strings.ToLower(benchmarkCase.str)
				}
			})
		}
	})
}
