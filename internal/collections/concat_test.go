// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestConcatKeyed(t *testing.T) {
	c1 := NewMap(variables.ArgsGet)
	c2 := NewMap(variables.ArgsPost)
	c3 := NewMap(variables.ArgsPath)

	c := NewConcatKeyed(variables.Args, c1, c2, c3)

	re1 := regexp.MustCompile("anim")
	re2 := regexp.MustCompile("pla")

	if want, have := "ARGS", c.Name(); want != have {
		t.Errorf("want %q, have %q", want, have)
	}

	assertValuesMatch(t, c.FindAll())

	c1.Add("animal", "cat")

	assertValuesMatch(t, c.FindAll(), "cat")
	assertValuesMatch(t, c.FindString("animal"), "cat")
	assertValuesMatch(t, c.FindString("plant"))
	assertValuesMatch(t, c.FindRegex(re1), "cat")
	assertValuesMatch(t, c.FindRegex(re2))

	if want, have := variables.Args, c.FindAll()[0].Variable(); want != have {
		t.Errorf("want %q, have %q", want, have)
	}

	c2.Add("animal", "dog")

	assertValuesMatch(t, c.FindAll(), "cat", "dog")
	assertValuesMatch(t, c.FindString("animal"), "cat", "dog")
	assertValuesMatch(t, c.FindString("plant"))
	assertValuesMatch(t, c.FindRegex(re1), "cat", "dog")
	assertValuesMatch(t, c.FindRegex(re2))

	c3.Add("plant", "palm")

	assertValuesMatch(t, c.FindAll(), "cat", "dog", "palm")
	assertValuesMatch(t, c.FindString("animal"), "cat", "dog")
	assertValuesMatch(t, c.FindString("plant"), "palm")
	assertValuesMatch(t, c.FindRegex(re1), "cat", "dog")
	assertValuesMatch(t, c.FindRegex(re2), "palm")
}

func TestConcatCollection(t *testing.T) {
	c1 := NewMap(variables.ArgsGet)
	c2 := NewMap(variables.ArgsPost)
	c3 := NewMap(variables.ArgsPath)

	c := NewConcatCollection(variables.Args, c1, c2, c3)

	if want, have := "ARGS", c.Name(); want != have {
		t.Errorf("want %q, have %q", want, have)
	}

	assertValuesMatch(t, c.FindAll())

	c1.Add("animal", "cat")

	assertValuesMatch(t, c.FindAll(), "cat")

	c2.Add("animal", "dog")

	assertValuesMatch(t, c.FindAll(), "cat", "dog")

	c3.Add("plant", "palm")

	assertValuesMatch(t, c.FindAll(), "cat", "dog", "palm")
}

func assertValuesMatch(t *testing.T, matches []types.MatchData, wantValues ...string) {
	t.Helper()

	haveValues := make([]string, len(matches))
	for i := range matches {
		haveValues[i] = matches[i].Value()
	}
	// String concat is the simplest way to compare and print a message without reflection
	if want, have := strings.Join(wantValues, ","), strings.Join(haveValues, ","); want != have {
		t.Errorf("want %q, have %q", want, have)
	}
}

// assertUnorderedValuesMatch function comes in handy for comparing map values, where the order is not guaranteed
func assertUnorderedValuesMatch(t *testing.T, matches []types.MatchData, wantValues ...string) {
	t.Helper()
	if len(matches) != len(wantValues) {
		t.Errorf("want %d matches, have %d", len(wantValues), len(matches))
	}
	foundSlice := make([]bool, len(wantValues))
	for _, want := range wantValues {
		found := false
		for i, have := range matches {
			if want == have.Value() && !foundSlice[i] {
				found = true
				foundSlice[i] = true
				break
			}
		}
		if !found {
			t.Errorf("want %q, have %q", want, matches)
		}
	}
}
