// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package collections

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/corazawaf/coraza/v3/types/variables"
)

// Case Insensitive Map
// This is for headers and other collections that are case insensitive
func TestMap(t *testing.T) {
	c := NewMap(variables.RequestHeaders)
	c.SetIndex("user", 1, "value")
	c.Set("user-agent", []string{"value2"})
	if c.Get("user")[0] != "value" {
		t.Error("Error setting index")
	}
	if len(c.FindAll()) == 0 {
		t.Error("Error finding all")
	}
	if len(c.FindString("a")) > 0 {
		t.Error("Error should not find string")
	}
	if l := len(c.FindRegex(regexp.MustCompile("user.*"))); l != 2 {
		t.Errorf("Error should find regex, got %d", l)
	}

	c.Add("user-agent", "value3")

	wantStr := `REQUEST_HEADERS:
    user: value
    user-agent: value2,value3
`

	if have := fmt.Sprint(c); have != wantStr {
		// Map order is not guaranteed, not pretty but checking twice is the simplest for now.
		wantStr = `REQUEST_HEADERS:
    user-agent: value2,value3
    user: value
`
		if have != wantStr {
			t.Errorf("String() = %q, want %q", have, wantStr)
		}
	}

	if c.Len() != len(c.data) {
		t.Fatal("The lengths are not equal.")
	}

}

// TestMapTotalValuesVsLen is a regression test for GHSA-3ww9-vw83-9w5x: Len
// counts distinct keys, so a caller enforcing an argument limit against Len
// was blind to many values piling up under one repeated key. TotalValues
// must count every value instead.
func TestMapTotalValuesVsLen(t *testing.T) {
	c := NewMap(variables.ArgsGet)
	for i := 0; i < 1000; i++ {
		c.Add("repeated", "v")
	}
	if c.Len() != 1 {
		t.Fatalf("expected Len() == 1 for a single repeated key, got %d", c.Len())
	}
	if c.TotalValues() != 1000 {
		t.Fatalf("expected TotalValues() == 1000, got %d", c.TotalValues())
	}

	c.Add("distinct", "v")
	if c.Len() != 2 {
		t.Fatalf("expected Len() == 2 after adding a distinct key, got %d", c.Len())
	}
	if c.TotalValues() != 1001 {
		t.Fatalf("expected TotalValues() == 1001, got %d", c.TotalValues())
	}
}

func TestMapTotalValuesEmpty(t *testing.T) {
	c := NewMap(variables.ArgsGet)
	if got := c.TotalValues(); got != 0 {
		t.Fatalf("expected TotalValues() == 0 for an empty map, got %d", got)
	}
}

// TestMapTotalValuesTracksAllMutations is a regression test for the counter
// TotalValues now maintains incrementally (see GHSA-6r3q-mjv7-xr8m follow-up:
// recomputing it by walking every key on each call made checkArgumentLimit
// quadratic). Every mutating method must keep the counter in sync, not just
// Add.
func TestMapTotalValuesTracksAllMutations(t *testing.T) {
	c := NewMap(variables.ArgsGet)

	c.Set("key", []string{"v1", "v2", "v3"})
	if got := c.TotalValues(); got != 3 {
		t.Fatalf("after Set with 3 values: expected TotalValues() == 3, got %d", got)
	}

	// Set overwriting the same key with fewer values must shrink the count,
	// not just grow it.
	c.Set("key", []string{"v1"})
	if got := c.TotalValues(); got != 1 {
		t.Fatalf("after Set shrinking to 1 value: expected TotalValues() == 1, got %d", got)
	}

	// SetIndex growing past the current length appends.
	c.SetIndex("key", 5, "v-at-5")
	if got := c.TotalValues(); got != 2 {
		t.Fatalf("after SetIndex append: expected TotalValues() == 2, got %d", got)
	}

	// SetIndex overwriting an existing index must not change the count.
	c.SetIndex("key", 0, "v1-overwritten")
	if got := c.TotalValues(); got != 2 {
		t.Fatalf("after SetIndex overwrite: expected TotalValues() == 2, got %d", got)
	}

	// SetIndex on a brand new key.
	c.SetIndex("new-key", 0, "v")
	if got := c.TotalValues(); got != 3 {
		t.Fatalf("after SetIndex on a new key: expected TotalValues() == 3, got %d", got)
	}

	c.Remove("key")
	if got := c.TotalValues(); got != 1 {
		t.Fatalf("after Remove: expected TotalValues() == 1, got %d", got)
	}

	// Removing a key that was never present must be a no-op.
	c.Remove("does-not-exist")
	if got := c.TotalValues(); got != 1 {
		t.Fatalf("after Remove of a missing key: expected TotalValues() == 1, got %d", got)
	}

	c.Reset()
	if got := c.TotalValues(); got != 0 {
		t.Fatalf("after Reset: expected TotalValues() == 0, got %d", got)
	}
}

func BenchmarkMapTotalValues(b *testing.B) {
	c := NewMap(variables.ArgsGet)
	for i := 0; i < 1000; i++ {
		c.Add("repeated", "v")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.TotalValues()
	}
}

// Case Sensitive Map
// This is for ARGS, ARGS_GET, ARGS_POST and other collections that are case sensitive
func TestNewCaseSensitiveKeyMap(t *testing.T) {
	c := NewCaseSensitiveKeyMap(variables.ArgsPost)
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

	c.Add("key2", "value3")

	wantStr := `ARGS_POST:
    key: value
    key2: value2,value3
`

	if have := fmt.Sprint(c); have != wantStr {
		// Map order is not guaranteed, not pretty but checking twice is the simplest for now.
		wantStr = `ARGS_POST:
    key2: value2,value3
    key: value
`
		if have != wantStr {
			t.Errorf("String() = %q, want %q", have, wantStr)
		}
	}

	if c.Len() != len(c.data) {
		t.Fatal("The lengths are not equal.")
	}

}

func TestFindAllBulkAllocIndependence(t *testing.T) {
	m := NewMap(variables.ArgsGet)
	m.Add("key1", "value1")
	m.Add("key2", "value2")
	m.Add("key3", "value3")

	results := m.FindAll()
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Mutate first result's value through the MatchData interface
	// and verify others are not affected
	values := make([]string, len(results))
	for i, r := range results {
		values[i] = r.Value()
	}

	// Verify all values are distinct and correct
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] {
			t.Errorf("duplicate value found: %s", v)
		}
		seen[v] = true
	}
	if !seen["value1"] || !seen["value2"] || !seen["value3"] {
		t.Errorf("expected value1, value2, value3 but got %v", values)
	}
}

func TestFindStringBulkAlloc(t *testing.T) {
	m := NewMap(variables.ArgsGet)
	m.Add("key", "val1")
	m.Add("key", "val2")

	results := m.FindString("key")
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Each result should have distinct values
	if results[0].Value() == results[1].Value() {
		t.Errorf("expected distinct values, got %q and %q", results[0].Value(), results[1].Value())
	}
}

func TestFindRegexBulkAlloc(t *testing.T) {
	m := NewMap(variables.ArgsGet)
	m.Add("abc", "val1")
	m.Add("abd", "val2")
	m.Add("xyz", "val3")

	re := regexp.MustCompile("^ab")
	results := m.FindRegex(re)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Verify keys match regex
	for _, r := range results {
		if r.Key() != "abc" && r.Key() != "abd" {
			t.Errorf("unexpected key: %s", r.Key())
		}
	}
}

func TestFindAllEmptyMap(t *testing.T) {
	m := NewMap(variables.ArgsGet)
	results := m.FindAll()
	if results != nil {
		t.Errorf("expected nil for empty map, got %v", results)
	}
}

func BenchmarkFindAll(b *testing.B) {
	b.ReportAllocs()
	m := NewMap(variables.RequestHeaders)
	for i := 0; i < 20; i++ {
		m.Add(fmt.Sprintf("x-header-%d", i), fmt.Sprintf("value-%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.FindAll()
	}
}

func BenchmarkFindRegex(b *testing.B) {
	b.ReportAllocs()
	m := NewMap(variables.RequestHeaders)
	for i := 0; i < 20; i++ {
		m.Add(fmt.Sprintf("x-header-%d", i), fmt.Sprintf("value-%d", i))
	}
	// Matches keys ending in 0-9 (x-header-0 .. x-header-9), roughly half.
	re := regexp.MustCompile(`^x-header-\d$`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.FindRegex(re)
	}
}

func BenchmarkFindString(b *testing.B) {
	b.ReportAllocs()
	m := NewMap(variables.RequestHeaders)
	// Single key with multiple values
	for i := 0; i < 20; i++ {
		m.Add("x-forwarded-for", fmt.Sprintf("10.0.0.%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.FindString("x-forwarded-for")
	}
}

func BenchmarkTxSetGet(b *testing.B) {
	keys := make(map[int]string, b.N)
	for i := 0; i < b.N; i++ {
		keys[i] = fmt.Sprintf("key%d", i)
	}
	c := NewCaseSensitiveKeyMap(variables.RequestHeaders)

	b.Run("Set", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Set(keys[i], []string{"value2"})
		}
	})
	b.Run("Get", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			c.Get(keys[i])
		}
	})
	b.ReportAllocs()
}
