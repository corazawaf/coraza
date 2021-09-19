// +build cgo

// Copyright (C) 2011 Florian Weimer <fw@deneb.enyo.de>

package regex

import (
	"testing"
)

func TestCompile(t *testing.T) {
	var check = func(p string, groups int) {
		re, err := Compile(p, 0)
		if err != nil {
			t.Error(p, err)
		}
		if g := re.Groups(); g != groups {
			t.Error(p, g)
		}
	}
	check("", 0)
	check("^", 0)
	check("^$", 0)
	check("()", 1)
	check("(())", 2)
	check("((?:))", 1)
}

func TestCompileFail(t *testing.T) {
	var check = func(p, msg string, off int) {
		_, err := Compile(p, 0)
		if err == nil {
			t.Error(p)
		} else {
			cerr := err.(*CompileError)
			switch {
			case cerr.Message != msg:
				t.Error(p, "Message", cerr.Message)
			case cerr.Offset != off:
				t.Error(p, "Offset", cerr.Offset)
			}
		}
	}
	check("(", "missing )", 1)
	check("\\", "\\ at end of pattern", 1)
	check("abc\\", "\\ at end of pattern", 4)
	check("abc\000", "NUL byte in pattern", 3)
	check("a\000bc", "NUL byte in pattern", 1)
}

func checkmatch1(t *testing.T, dostring bool, m *Matcher,
	pattern, subject string, args ...interface{}) {
	re := MustCompile(pattern, 0)
	var prefix string
	if dostring {
		if m == nil {
			m = re.MatcherString(subject, 0)
		} else {
			m.ResetString(re, subject, 0)
		}
		prefix = "string"
	} else {
		if m == nil {
			m = re.Matcher([]byte(subject), 0)
		} else {
			m.Reset(re, []byte(subject), 0)
		}
		prefix = "[]byte"
	}
	if len(args) == 0 {
		if m.Matches() {
			t.Error(prefix, pattern, subject, "!Matches")
		}
	} else {
		if !m.Matches() {
			t.Error(prefix, pattern, subject, "Matches")
			return
		}
		if m.Groups() != len(args)-1 {
			t.Error(prefix, pattern, subject, "Groups", m.Groups())
			return
		}
		for i, arg := range args {
			if s, ok := arg.(string); ok {
				if !m.Present(i) {
					t.Error(prefix, pattern, subject,
						"Present", i)

				}
				if g := string(m.Group(i)); g != s {
					t.Error(prefix, pattern, subject,
						"Group", i, g, "!=", s)
				}
				if g := m.GroupString(i); g != s {
					t.Error(prefix, pattern, subject,
						"GroupString", i, g, "!=", s)
				}
			} else {
				if m.Present(i) {
					t.Error(prefix, pattern, subject,
						"!Present", i)
				}
			}
		}
	}
}

func TestMatcher(t *testing.T) {
	var m Matcher
	check := func(pattern, subject string, args ...interface{}) {
		checkmatch1(t, false, nil, pattern, subject, args...)
		checkmatch1(t, true, nil, pattern, subject, args...)
		checkmatch1(t, false, &m, pattern, subject, args...)
		checkmatch1(t, true, &m, pattern, subject, args...)
	}

	check(`^$`, "", "")
	check(`^abc$`, "abc", "abc")
	check(`^(X)*ab(c)$`, "abc", "abc", nil, "c")
	check(`^(X)*ab()c$`, "abc", "abc", nil, "")
	check(`^.*$`, "abc", "abc")
	check(`^.*$`, "a\000c", "a\000c")
	check(`^(.*)$`, "a\000c", "a\000c", "a\000c")
	check(`def`, "abcdefghi", "def")
}

func TestCaseless(t *testing.T) {
	m := MustCompile("abc", CASELESS).MatcherString("...Abc...", 0)
	if !m.Matches() {
		t.Error("CASELESS")
	}
	m = MustCompile("abc", 0).MatcherString("Abc", 0)
	if m.Matches() {
		t.Error("!CASELESS")
	}
}
