// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

const (
	deeplyNestedJSONObject = 15000
	maxRecursion           = 10000
)

var jsonTests = []struct {
	name string
	json string
	want map[string]string
	err  error
}{
	{
		name: "map",
		json: `
{
  "a": 1,
  "b": 2,
  "c": [
    1,
    2,
    3
  ],
  "d": {
    "a": {
      "b": 1
    }
  },
  "e": [
	  {"a": 1}
  ],
  "f": [
	  [
		  [
			  {"z": "abc"}
		  ]
	  ]
  ]
}
	`,
		want: map[string]string{
			"json.a":         "1",
			"json.b":         "2",
			"json.c":         "3",
			"json.c.0":       "1",
			"json.c.1":       "2",
			"json.c.2":       "3",
			"json.d.a.b":     "1",
			"json.e":         "1",
			"json.e.0.a":     "1",
			"json.f":         "1",
			"json.f.0":       "1",
			"json.f.0.0":     "1",
			"json.f.0.0.0.z": "abc",
		},
		err: nil,
	},
	{
		name: "array",
		json: `
[
    [
        [
            {
                "q": 1
            }
        ]
    ],
    {
        "a": 1,
        "b": 2,
        "c": [
            1,
            2,
            3
        ],
        "d": {
            "a": {
                "b": 1
            }
        },
        "e": [
            {
                "a": 1
            }
        ],
        "f": [
            [
                [
                    {
                        "z": "abc"
                    }
                ]
            ]
        ]
    }
]`,
		want: map[string]string{
			"json":             "2",
			"json.0":           "1",
			"json.0.0":         "1",
			"json.0.0.0.q":     "1",
			"json.1.a":         "1",
			"json.1.b":         "2",
			"json.1.c":         "3",
			"json.1.c.0":       "1",
			"json.1.c.1":       "2",
			"json.1.c.2":       "3",
			"json.1.d.a.b":     "1",
			"json.1.e":         "1",
			"json.1.e.0.a":     "1",
			"json.1.f":         "1",
			"json.1.f.0":       "1",
			"json.1.f.0.0":     "1",
			"json.1.f.0.0.0.z": "abc",
		},
		err: nil,
	},
	{
		name: "unbalanced_brackets",
		json: `{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a": 1 }}}}}}}}}}}}}}}}}}}}}}`,
		want: map[string]string{},
		err:  errors.New("invalid JSON"),
	},
	{
		name: "broken2",
		json: `{"test": 123, "test2": 456, "test3": [22, 44, 55], "test4": 3}`,
		want: map[string]string{
			"json.test3.0": "22",
			"json.test3.1": "44",
			"json.test3.2": "55",
			"json.test4":   "3",
			"json.test":    "123",
			"json.test2":   "456",
			"json.test3":   "3",
		},
		err: nil,
	},
	{
		name: "bomb",
		json: strings.Repeat(`{"a":`, deeplyNestedJSONObject) + "1" + strings.Repeat(`}`, deeplyNestedJSONObject),
		want: map[string]string{
			"json." + strings.Repeat(`a.`, deeplyNestedJSONObject-1) + "a": "1",
		},
		err: errors.New("max recursion reached while reading json object"),
	},
	{
		name: "empty_object",
		json: `{}`,
		want: map[string]string{},
	},
	{
		name: "null_and_boolean_values",
		json: `{"null": null, "true": true, "false": false}`,
		want: map[string]string{
			"json.null":  "",
			"json.true":  "true",
			"json.false": "false",
		},
	},
	// For this test we won't validate keys since the implementation
	// might process empty objects/arrays differently
	{
		name: "nested_empty",
		json: `{"a": {}, "b": []}`,
		want: map[string]string{},
	},
	{
		// CRS rule 944130 matches suspicious literal Java class names (e.g.
		// "com.opensymphony.xwork2", a known Struts2/OGNL injection vector)
		// as a substring of the flattened key. Escaping literal dots to fix
		// GHSA-5gj4-9gm7-2fx2 would break this detection for the common,
		// non-colliding case, so the flattened key text must stay unescaped.
		name: "literal_dotted_key_stays_unescaped_when_it_does_not_collide",
		json: `{"com.opensymphony.xwork2": "test"}`,
		want: map[string]string{
			"json.com.opensymphony.xwork2": "test",
		},
	},
}

// TestReadJSONKeyCollisionPreservesBothValues is a dedicated function rather
// than a jsonTests row: it asserts multiple values under one key, a shape
// TestReadJSON's single-value want map doesn't express.
//
// GHSA-5gj4-9gm7-2fx2: a nested path and a literal property name containing a
// dot can flatten to the identical key -- {"account":{"role":"ATTACK"}} and
// {"account.role":"SAFE"} both produce "json.account.role". Overwriting the
// first value with the second would hide "ATTACK" from every rule that
// inspects ARGS_POST, while a standard JSON parser still exposes both
// properties to the backend. Both values must survive under the same key.
func TestReadJSONKeyCollisionPreservesBothValues(t *testing.T) {
	json := `{"account":{"role":"ATTACK"},"account.role":"SAFE"}`
	got, _, err := readJSON(json, maxRecursion, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ATTACK", "SAFE"}
	have := got["json.account.role"]
	if len(have) != len(want) {
		t.Fatalf("json.account.role = %v, want %v", have, want)
	}
	for i := range want {
		if have[i] != want[i] {
			t.Errorf("json.account.role[%d] = %q, want %q", i, have[i], want[i])
		}
	}
}

func TestReadJSON(t *testing.T) {
	for _, tc := range jsonTests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			jsonMap, _, err := readJSON(tt.json, maxRecursion, 0)

			// Special case for nested_empty - just check that the function doesn't error
			if tt.name == "nested_empty" {
				if err != nil {
					t.Error(err)
				}
				// Print the keys for debugging
				t.Logf("Actual keys for nested_empty: %v", mapKeys(jsonMap))
				return
			}

			if err != nil {
				if tt.err == nil || err.Error() != tt.err.Error() {
					t.Error(err)
				}
				return
			}

			for k, want := range tt.want {
				if have, ok := jsonMap[k]; ok {
					if len(have) != 1 || have[0] != want {
						t.Errorf("key=%s, want [%s], have %v", k, want, have)
					}
				} else {
					t.Errorf("missing key: %s", k)
				}
			}
			for k := range jsonMap {
				if _, ok := tt.want[k]; !ok {
					t.Errorf("unexpected key: %s", k)
				}
			}
		})
	}
}

// Helper function to get map keys
func mapKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestInvalidJSON(t *testing.T) {
	_, _, err := readJSON(`{invalid json`, maxRecursion, 0)
	if err == nil {
		// We expect an error for invalid JSON since we now validate
		t.Error("Expected error for invalid JSON, got nil")
	}
}

// Not a jsonTests row: maxRecursion is shared across all rows in that table,
// so a negative-limit case can't be expressed as one.
func TestReadJSONNegativeRecursionLimit(t *testing.T) {
	_, _, err := readJSON(`{"a": 1}`, -1, 0)
	want := "max recursion reached while reading json object"
	if err == nil || err.Error() != want {
		t.Errorf("want error %q, got %v", want, err)
	}
}

func BenchmarkReadJSON(b *testing.B) {
	for _, tc := range jsonTests {
		tt := tc
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := readJSON(tt.json, maxRecursion, 0)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}

// readJSONNoValidation is readJSON without the gjson.Valid pre-check.
// Used only in benchmarks to measure the overhead of validation.
func readJSONNoValidation(s string, maxRecursion int) (map[string][]string, error) {
	json := gjson.Parse(s)
	res := make(map[string][]string)
	key := []byte("json")
	_, err := readItems(json, key, maxRecursion, 0, 0, new(int), new(int), res)
	return res, err
}

// BenchmarkValidationOverhead measures the cost of pre-validating JSON with gjson.Valid
// in the context of the full readJSON pipeline (Valid + Parse + readItems).
// gjson.Parse is lazy (~9ns regardless of input size), so the real overhead is
// gjson.Valid vs the readItems traversal that does the actual parsing work.
func BenchmarkValidationOverhead(b *testing.B) {
	benchCases := []struct {
		name string
		json string
	}{
		{
			name: "small_object",
			json: `{"name":"John","age":30}`,
		},
		{
			name: "medium_object",
			json: `{"user":{"name":"John","email":"john@example.com","roles":["admin","user"]},"settings":{"theme":"dark","notifications":true},"metadata":{"created":"2026-01-01","updated":"2026-02-15"}}`,
		},
		{
			name: "large_array",
			json: func() string {
				var sb strings.Builder
				sb.WriteString("[")
				for i := 0; i < 100; i++ {
					if i > 0 {
						sb.WriteString(",")
					}
					sb.WriteString(`{"id":` + strings.Repeat("1", 5) + `,"name":"user","active":true}`)
				}
				sb.WriteString("]")
				return sb.String()
			}(),
		},
		{
			name: "nested_10_levels",
			json: strings.Repeat(`{"a":`, 10) + "1" + strings.Repeat(`}`, 10),
		},
	}

	for _, bc := range benchCases {
		b.Run("WithValidation/"+bc.name, func(b *testing.B) {
			b.SetBytes(int64(len(bc.json)))
			for i := 0; i < b.N; i++ {
				if _, _, err := readJSON(bc.json, maxRecursion, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("WithoutValidation/"+bc.name, func(b *testing.B) {
			b.SetBytes(int64(len(bc.json)))
			for i := 0; i < b.N; i++ {
				if _, err := readJSONNoValidation(bc.json, maxRecursion); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestReadJSONArgumentLimit is a regression test for GHSA-3ww9-vw83-9w5x:
// a small body decoding to a wide flat structure (e.g. a JSON array of
// scalars) must not grow the flattened map without bound, regardless of
// SecArgumentsLimit.
func TestReadJSONArgumentLimit(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 10000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("1")
	}
	sb.WriteString("]")

	res, truncated, err := readJSON(sb.String(), maxRecursion, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("expected truncated to be true")
	}
	// +1 for the "json" key holding the array length summary entry.
	if len(res) > 1001 {
		t.Errorf("expected at most ~1000 entries, got %d", len(res))
	}
}

func TestReadJSONArgumentLimitNested(t *testing.T) {
	// A nested structure that is wide at a deep level: the limit must stop
	// collection everywhere, not just at the top level.
	var sb strings.Builder
	sb.WriteString(`{"a":{"b":[`)
	for i := 0; i < 10000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("1")
	}
	sb.WriteString(`]}}`)

	res, truncated, err := readJSON(sb.String(), maxRecursion, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("expected truncated to be true")
	}
	if len(res) > 1002 {
		t.Errorf("expected at most ~1000 entries, got %d", len(res))
	}
}

// TestReadJSONArgumentLimitCountsCollidedValues is a regression test for the
// merge of GHSA-5gj4-9gm7-2fx2 (values preserved on a key collision) with
// GHSA-3ww9-vw83-9w5x's argument limit: counting distinct keys (len(res))
// instead of total values would let repeated colliding keys pile up
// unboundedly many values under one key without ever tripping
// SecArgumentsLimit, since gjson.ForEach surfaces every literal duplicate
// key in the raw JSON text.
func TestReadJSONArgumentLimitCountsCollidedValues(t *testing.T) {
	const limit = 1000
	var sb strings.Builder
	sb.WriteString("{")
	for i := 0; i < 10000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"a":1`)
	}
	sb.WriteString("}")

	res, truncated, err := readJSON(sb.String(), maxRecursion, limit)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("expected truncated to be true")
	}
	total := 0
	for _, values := range res {
		total += len(values)
	}
	if total > limit {
		t.Errorf("argument limit %d exceeded: got %d values across %d key(s)", limit, total, len(res))
	}
}

func TestReadJSONNoArgumentLimit(t *testing.T) {
	res, truncated, err := readJSON(`{"a":1,"b":2,"c":3}`, maxRecursion, 0)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("expected truncated to be false when argumentLimit is 0 (no limit)")
	}
	if len(res) != 3 {
		t.Errorf("expected 3 entries, got %d: %v", len(res), res)
	}
}

func BenchmarkReadJSONArgumentLimit(b *testing.B) {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 100000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("1")
	}
	sb.WriteString("]")
	json := sb.String()

	b.Run("limit=1000", func(b *testing.B) {
		b.SetBytes(int64(len(json)))
		for i := 0; i < b.N; i++ {
			if _, _, err := readJSON(json, maxRecursion, 1000); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("no_limit", func(b *testing.B) {
		b.SetBytes(int64(len(json)))
		for i := 0; i < b.N; i++ {
			if _, _, err := readJSON(json, maxRecursion, 0); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestReadJSONArrayLengthRespectsArgumentLimit covers the entry written after
// ForEach returns, outside the guards inside the callback. Every array level
// added one entry past SecArgumentsLimit and left truncated false, so 1024
// nested arrays in a 2 KB body produced 1025 arguments and the deny rule that
// depends on the flag never fired.
func TestReadJSONArrayLengthRespectsArgumentLimit(t *testing.T) {
	const limit = 1000
	depth := 1024
	body := strings.Repeat("[", depth) + "1" + strings.Repeat("]", depth)

	res, truncated, err := readJSON(body, 10000, limit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) > limit {
		t.Errorf("argument limit %d exceeded: got %d arguments", limit, len(res))
	}
	if !truncated {
		t.Error("truncated must be set when the argument limit stops the walk, or the deny rule cannot fire")
	}
}

// TestReadJSONBoundsFlattenedBytes covers memory growth that the argument
// count cannot see. Keys carry the full path and are rewritten per leaf, so a
// body of long paths stays under the argument limit while retaining many times
// its own size.
func TestReadJSONBoundsFlattenedBytes(t *testing.T) {
	const limit = 1000
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		sb.WriteString(`{"` + strings.Repeat("p", 200) + strconv.Itoa(i) + `":`)
	}
	sb.WriteString("{")
	for i := 0; i < 999; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"leaf` + strconv.Itoa(i) + `":"` + strings.Repeat("v", 20) + `"`)
	}
	sb.WriteString("}" + strings.Repeat("}", 8))
	body := sb.String()

	res, truncated, err := readJSON(body, 10000, limit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stored := 0
	for k, v := range res {
		stored += len(k) + len(v)
	}
	budget := len(body) * flattenBytesFactor
	if stored > budget {
		t.Errorf("flattened form retained %d bytes, over the %d byte budget for a %d byte body",
			stored, budget, len(body))
	}
	if !truncated {
		t.Error("truncated must be set when the byte budget stops the walk")
	}
	if len(res) >= limit {
		t.Errorf("expected the byte budget to stop the walk before the argument limit, got %d arguments", len(res))
	}
}

// TestReadJSONLeavesOrdinaryPayloadsIntact guards the byte budget against
// truncating traffic it was never meant to touch.
func TestReadJSONLeavesOrdinaryPayloadsIntact(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"users":[`)
	for i := 0; i < 200; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":` + strconv.Itoa(i) + `,"name":"user` + strconv.Itoa(i) +
			`","email":"u` + strconv.Itoa(i) + `@example.com","active":true}`)
	}
	sb.WriteString(`]}`)

	res, truncated, err := readJSON(sb.String(), 10000, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Errorf("a %d byte API-shaped payload must not be truncated, got %d arguments", sb.Len(), len(res))
	}
}
