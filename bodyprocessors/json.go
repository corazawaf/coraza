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
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/corazawaf/coraza/v2/types/variables"
)

type jsonBodyProcessor struct {
	collections CollectionsMap
}

func (js *jsonBodyProcessor) Read(reader io.Reader, _ Options) error {
	// dump reader to byte array
	var data []byte
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		data = append(data, buf[:n]...)
	}
	fields, err := jsonToMap(data)
	if err != nil {
		return err
	}
	f := map[string][]string{}
	names := []string{}
	for key, value := range fields {
		f[key] = []string{value}
		names = append(names, key)
	}
	js.collections = CollectionsMap{
		variables.Args:     f,
		variables.ArgsPost: f,
		variables.ArgsPostNames: map[string][]string{
			"": names,
		},
	}
	return nil
}

func (js *jsonBodyProcessor) Collections() CollectionsMap {
	return js.collections
}

func (js *jsonBodyProcessor) Find(expr string) (map[string][]string, error) {
	return nil, nil
}

func (js *jsonBodyProcessor) VariableHook() variables.RuleVariable {
	return variables.JSON
}

// Transform JSON to a map[string]string
// Example input: {"data": {"name": "John", "age": 30}, "items": [1,2,3]}
// Example output: map[string]string{"json.data.name": "John", "json.data.age": "30", "json.items.0": "1", "json.items.1": "2", "json.items.2": "3"}
// Example input: [{"data": {"name": "John", "age": 30}, "items": [1,2,3]}]
// Example output: map[string]string{"json.0.data.name": "John", "json.0.data.age": "30", "json.0.items.0": "1", "json.0.items.1": "2", "json.0.items.2": "3"}
// TODO add some anti DOS protection
func jsonToMap(data []byte) (map[string]string, error) {
	var (
		result interface{}
		m      map[string]string
		err    error
	)
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	switch result := result.(type) {
	case map[string]interface{}:
		m, err = interfaceToMap(result)
		if err != nil {
			return nil, err
		}
	case []interface{}:
		m, err = arrayToMap(result)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid JSON")
	}

	res := make(map[string]string)
	for key, value := range m {
		res["json."+key] = value
	}
	return res, nil
}

// Transform []interface{} into map[string]string recursively
func arrayToMap(data []interface{}) (map[string]string, error) {
	result := make(map[string]string)
	for index, value := range data {
		switch value := value.(type) {
		case map[string]interface{}:
			m, err := interfaceToMap(value)
			if err != nil {
				return nil, err
			}
			for k, v := range m {
				result[fmt.Sprintf("%d.%s", index, k)] = v
			}
		case []interface{}:
			subMap, err := arrayToMap(value)
			if err != nil {
				return nil, err
			}
			for k, v := range subMap {
				result[fmt.Sprintf("%d.%s", index, k)] = v
			}
		default:
			return nil, fmt.Errorf("invalid JSON")
		}
	}
	return result, nil
}

// Transform map[string]interface{} into map[string]string recursively
func interfaceToMap(data map[string]interface{}) (map[string]string, error) {
	result := make(map[string]string)
	for key, value := range data {
		switch value := value.(type) {
		case []interface{}:
			m := map[string]interface{}{}
			for i, v := range value {
				m[strconv.Itoa(i)] = v
			}
			// we set the parent key to count the number of items
			result[key] = strconv.Itoa(len(m))

			m2, err := interfaceToMap(m)
			if err != nil {
				return nil, err
			}
			for k, v := range m2 {
				result[fmt.Sprintf("%s.%s", key, k)] = v
			}
		case string:
			result[key] = value
		case int:
			result[key] = strconv.Itoa(value)
		case nil:
			// TODO check if we ignore this or let it pass
			result[key] = ""
		case float64:
			result[key] = strconv.FormatFloat(value, 'f', -1, 64)
		case bool:
			result[key] = strconv.FormatBool(value)
		case map[string]interface{}:
			subMap, err := interfaceToMap(value)
			if err != nil {
				return nil, err
			}
			for k, v := range subMap {
				result[fmt.Sprintf("%s.%s", key, k)] = v
			}
		default:
			return nil, fmt.Errorf("failed to unmarshall %s", value)
		}
	}
	return result, nil
}

var (
	_ BodyProcessor = &jsonBodyProcessor{}
)
