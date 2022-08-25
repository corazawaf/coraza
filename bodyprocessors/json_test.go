// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"testing"
)

// Tests JSONToMap
func TestJSONToMap(t *testing.T) {
	var (
		jsonMapString = `
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
	`
		jsonArrayString = `
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
]
`
	)
	mapAsserts := map[string]string{
		"json.a":         "1",
		"json.b":         "2",
		"json.c":         "3",
		"json.c.0":       "1",
		"json.c.1":       "2",
		"json.c.2":       "3",
		"json.d.a.b":     "1",
		"json.e.0.a":     "1",
		"json.f.0.0.0.z": "abc",
	}
	jsonMap, err := jsonToMap([]byte(jsonMapString))
	if err != nil {
		t.Error(err)
	}

	for k, v := range mapAsserts {
		if jsonMap[k] != v {
			t.Errorf("Expected %s=%s", k, v)
		}
	}

	arrayAsserts := map[string]string{
		"json.0.0.0.q":     "1",
		"json.1.a":         "1",
		"json.1.b":         "2",
		"json.1.c":         "3",
		"json.1.c.0":       "1",
		"json.1.c.1":       "2",
		"json.1.c.2":       "3",
		"json.1.d.a.b":     "1",
		"json.1.e.0.a":     "1",
		"json.1.f.0.0.0.z": "abc",
	}
	jsonArray, err := jsonToMap([]byte(jsonArrayString))
	if err != nil {
		t.Error(err)
	}
	for k, v := range arrayAsserts {
		if jsonArray[k] != v {
			t.Errorf("Expected %s=%s", k, v)
		}
	}
}
