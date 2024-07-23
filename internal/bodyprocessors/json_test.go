// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"strings"
	"testing"
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
		name: "broken1", # this json test has more opening brackets than closing, so it is broken
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
}

func TestReadJSON(t *testing.T) {
	for _, tc := range jsonTests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			jsonMap, err := readJSON(strings.NewReader(tt.json), maxRecursion)
			for k, want := range tt.want {
				if err != nil && err.Error() == tt.err.Error() {
					continue
				} else if err != nil {
					t.Error(err)
				}
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

func BenchmarkReadJSON(b *testing.B) {
	for _, tc := range jsonTests {
		tt := tc
		b.Run(tt.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := readJSON(strings.NewReader(tt.json), maxRecursion)
				if err != nil {
					b.Error(err)
				}
			}
		})
	}
}
