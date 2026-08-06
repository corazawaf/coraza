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

	"github.com/corazawaf/coraza/v3/internal/corazarules"
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

func TestAddWithLowerKey(t *testing.T) {
	m := NewMap(variables.ArgsGet)
	m.AddWithLowerKey("Content-Type", "content-type", "text/html")

	results := m.FindString("content-type")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Key() != "Content-Type" {
		t.Errorf("expected original case key 'Content-Type', got %q", results[0].Key())
	}
	if results[0].Value() != "text/html" {
		t.Errorf("expected value 'text/html', got %q", results[0].Value())
	}
}

func TestFindAllPopulatesLowerKey(t *testing.T) {
	m := NewMap(variables.ArgsGet)
	m.Add("Content-Type", "text/html")

	results := m.FindAll()
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Access the MatchData to check LowerKey_ is populated
	md, ok := results[0].(*corazarules.MatchData)
	if !ok {
		t.Fatal("expected *corazarules.MatchData")
	}
	if md.LowerKey_ != "content-type" {
		t.Errorf("expected LowerKey_ 'content-type', got %q", md.LowerKey_)
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
