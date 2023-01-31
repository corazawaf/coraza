// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"regexp"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestNamedCollection(t *testing.T) {
	c := NewNamedCollection(variables.ArgsPost)

	// Same as collection_map_test
	c.SetIndex("key", 1, "value")
	c.Set("key2", []string{"value2"})
	if c.Get("key")[0] != "value" {
		t.Error("Error setting index")
	}
	if len(c.FindAll()) == 0 {
		t.Error("Error finding all")
	}
	if len(c.FindString("a")) > 0 {
		t.Error("Error should not find string")
	}
	if l := len(c.FindRegex(regexp.MustCompile("k.*"))); l != 2 {
		t.Errorf("Error should find regex, got %d", l)
	}

	// Now test names

	names := c.Names(variables.ArgsPostNames)
	if want, have := "ARGS_POST_NAMES", names.Name(); want != have {
		t.Errorf("want %q, have %q", want, have)
	}

	assertValuesMatch(t, names.FindAll(), "key", "key2")
	c.Add("key", "value2")
	assertValuesMatch(t, names.FindAll(), "key", "key2")
	// While selection operators will treat this as case-insensitive, names should have all names
	// as-is.
	c.Add("Key", "value3")
	assertValuesMatch(t, names.FindAll(), "key", "key2", "Key")
	c.Remove("key2")
	assertValuesMatch(t, names.FindAll(), "key", "Key")
}
