// Copyright 2022 Juan Pablo Tosso
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bodyprocessors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

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
	require.NoError(t, err)
	for k, v := range arrayAsserts {
		assert.Equal(t, v, jsonArray[k])
	}
}
