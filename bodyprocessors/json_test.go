// Copyright 2021 Juan Pablo Tosso
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
)

// Tests JSONToMap
func TestJSONToMap(t *testing.T) {
	var jsonString = `
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
	asserts := map[string]string{
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
	jsonMap, err := jsonToMap([]byte(jsonString))
	if err != nil {
		t.Error(err)
	}
	//fmt.Println(jsonMap)
	for k, v := range asserts {
		if jsonMap[k] != v {
			t.Errorf("Expected %s=%s", k, v)
		}
	}
}
