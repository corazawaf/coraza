//go:build !cgo
// +build !cgo

// Copyright 2021 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	match := m.rx.FindAllString(input, 10)
	if len(match) == 0 {
		return false
	}
	m.match = []string{input}
	m.match = append(m.match, match...)
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

func Compile(input string, flags int) (Regexp, error) {
	pattern, err := regexp.Compile(input)
	return Regexp{
		pattern: pattern,
	}, err
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
