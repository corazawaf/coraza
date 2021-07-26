// +build !cgo,never
// Copyright (c) 2011 Florian Weimer. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package pcre provides access to the Perl Compatible Regular
// Expresion library, PCRE.
//
// It implements two main types, Regexp and Matcher.  Regexp objects
// store a compiled regular expression. They consist of two immutable
// parts: pcre and pcre_extra. Compile()/MustCompile() initialize pcre.
// Calling Study() on a compiled Regexp initializes pcre_extra.
// Compilation of regular expressions using Compile or MustCompile is
// slightly expensive, so these objects should be kept and reused,
// instead of compiling them from scratch for each matching attempt.
// CompileJIT and MustCompileJIT are way more expensive, because they
// run Study() after compiling a Regexp, but they tend to give
// much better perfomance:
// http://sljit.sourceforge.net/regex_perf.html
//
// Matcher objects keeps the results of a match against a []byte or
// string subject.  The Group and GroupString functions provide access
// to capture groups; both versions work no matter if the subject was a
// []byte or string, but the version with the matching type is slightly
// more efficient.
//
// Matcher objects contain some temporary space and refer the original
// subject.  They are mutable and can be reused (using Match,
// MatchString, Reset or ResetString).
//
// For details on the regular expression language implemented by this
// package and the flags defined below, see the PCRE documentation.
// http://www.pcre.org/pcre.txt

package regex

import (
	"regexp"
)

type Matcher struct {
	input string
	rx    *regexp.Regexp

	count int
	match []string
}

func (m *Matcher) Matches() bool {
	return m.count > 0
}

func (m *Matcher) MatchString(input string, flags int) bool {
	m.match = []string{input}
	m.match = append(m.match, m.rx.FindAllString(input, 0)...)
	m.count = len(m.match)
	return m.count > 0
}

func (m *Matcher) Match(input []byte, flags int) bool {
	return m.MatchString(string(input), 0)
}

func (m *Matcher) Groups() int {
	return m.count
}

func (m *Matcher) Index() []int {
	return m.rx.FindStringIndex(m.input)
}

func (m *Matcher) GroupString(index int) string {
	if m.count > index {
		return m.match[index]
	}
	return ""
}

type Regexp struct {
	pattern *regexp.Regexp
}

func (rx *Regexp) ReplaceAllString(input string, asdf string, flags int) string {
	return input
}

func (rx *Regexp) Matcher(input []byte, flags int) Matcher {
	return rx.MatcherString(string(input), 0)
}

func (rx *Regexp) NewMatcher() Matcher {
	return rx.MatcherString("", 0)
}

func (rx *Regexp) MatcherString(input string, flags int) Matcher {
	m := Matcher{
		input: input,
		rx:    rx.pattern,
	}
	m.MatchString(input, 0)
	return m
}

func MustCompile(input string, flags int) Regexp {
	pattern, _ := regexp.Compile(input)
	return Regexp{
		pattern: pattern,
	}
}

func MustCompile(input string, flags int) Regexp {
	pattern, err := regexp.Compile(input)
	if err != nil {
		panic(err)
	}
	return Regexp{
		pattern: pattern,
	}
}
