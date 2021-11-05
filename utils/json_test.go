package utils

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
		"json.c.0":       "1",
		"json.c.1":       "2",
		"json.c.2":       "3",
		"json.d.a.b":     "1",
		"json.e.0.a":     "1",
		"json.f.0.0.0.z": "abc",
	}
	jsonMap, err := JSONToMap(jsonString)
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
