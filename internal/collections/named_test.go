// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestNamedCollection(t *testing.T) {
	c := NewNamedCollection(variables.ArgsPost)
	if c.Name() != "ARGS_POST" {
		t.Error("Error getting name")
	}

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
	wantStr := `ARGS_POST:
    key: value
    key2: value2
`
	if have := fmt.Sprint(c); have != wantStr {
		// Map order is not guaranteed, not pretty but checking twice is the simplest for now.
		wantStr = `ARGS_POST:
    key2: value2
    key: value
`
		if have != wantStr {
			t.Errorf("String() = %q, want %q", have, wantStr)
		}
	}

	// Now test names

	names := c.Names(variables.ArgsPostNames)
	if want, have := "ARGS_POST_NAMES", names.Name(); want != have {
		t.Errorf("want %q, have %q", want, have)
	}

	assertUnorderedValuesMatch(t, names.FindAll(), "key", "key2")
	if want, have := "ARGS_POST_NAMES: key,key2", fmt.Sprint(names); want != have {
		if want := "ARGS_POST_NAMES: key2,key"; want != have {
			t.Errorf("want %q, have %q", want, have)
		}
	}
	c.Add("key", "value2")
	assertUnorderedValuesMatch(t, names.FindAll(), "key", "key", "key2")
	if want, have := "ARGS_POST_NAMES: key,key,key2", fmt.Sprint(names); want != have {
		if want := "ARGS_POST_NAMES: key2,key,key"; want != have {
			t.Errorf("want %q, have %q", want, have)
		}
	}
	// While selection operators will treat this as case-insensitive, names should have all names
	// as-is.
	c.Add("Key", "value3")
	assertUnorderedValuesMatch(t, names.FindAll(), "key", "key", "Key", "key2")
	if want, have := "ARGS_POST_NAMES: key2,key,key,Key", fmt.Sprint(names); want != have {
		if want := "ARGS_POST_NAMES: key,key,Key,key2"; want != have {
			t.Errorf("want %q, have %q", want, have)
		}
	}
	c.Remove("key2")
	assertUnorderedValuesMatch(t, names.FindAll(), "key", "key", "Key")
	if want, have := "ARGS_POST_NAMES: key,key,Key", fmt.Sprint(names); want != have {
		t.Errorf("want %q, have %q", want, have)
	}

	if c.Len() != len(c.data) {
		t.Fatal("The lengths are not equal.")
	}

}
