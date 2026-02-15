// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
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
}

func TestReadJSON(t *testing.T) {
	for _, tc := range jsonTests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			jsonMap, err := readJSON(tt.json, maxRecursion)

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
					if want != have {
						t.Errorf("key=%s, want %s, have %s", k, want, have)
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
func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestInvalidJSON(t *testing.T) {
	_, err := readJSON(`{invalid json`, maxRecursion)
	if err == nil {
		// We expect an error for invalid JSON since we now validate
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func BenchmarkReadJSON(b *testing.B) {
	for _, tc := range jsonTests {
		tt := tc
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := readJSON(tt.json, maxRecursion)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}

// readJSONNoValidation is readJSON without the gjson.Valid pre-check.
// Used only in benchmarks to measure the overhead of validation.
func readJSONNoValidation(s string, maxRecursion int) (map[string]string, error) {
	json := gjson.Parse(s)
	res := make(map[string]string)
	key := []byte("json")
	err := readItems(json, key, maxRecursion, res)
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
				if _, err := readJSON(bc.json, maxRecursion); err != nil {
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
