package utils

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// Transform JSON to a map[string]string
// Example input: {"data": {"name": "John", "age": 30}, "items": [1,2,3]}
// Example output: map[string]string{"json.data.name": "John", "json.data.age": "30", "json.items.0": "1", "json.items.1": "2", "json.items.2": "3"}
func JSONToMap(data string) (map[string]string, error) {
	result := make(map[string]interface{})
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	m, err := interfaceToMap(result)
	if err != nil {
		return nil, err
	}
	res := make(map[string]string)
	for key, value := range m {
		res["json."+key] = value
	}
	return res, nil
}

// Transform map[string]interface{} into map[string]string recursively
func interfaceToMap(data map[string]interface{}) (map[string]string, error) {
	result := make(map[string]string)
	for key, value := range data {
		switch value.(type) {
		case []interface{}:
			m := map[string]interface{}{}
			for i, v := range value.([]interface{}) {
				m[strconv.Itoa(i)] = v
			}
			if m2, err := interfaceToMap(m); err != nil {
				return nil, err
			} else {
				for key2, value2 := range m2 {
					result[key+"."+key2] = value2
				}
			}
		case string:
			result[key] = value.(string)
		case int:
			result[key] = strconv.Itoa(value.(int))
		case nil:
			// TODO check if we ignore this or let it pass
			result[key] = ""
		case float64:
			result[key] = strconv.FormatFloat(value.(float64), 'f', -1, 64)
		case bool:
			result[key] = strconv.FormatBool(value.(bool))
		case map[string]interface{}:
			submap, err := interfaceToMap(value.(map[string]interface{}))
			if err != nil {
				return nil, err
			}
			for subkey, subvalue := range submap {
				result[key+"."+subkey] = subvalue
			}
		default:
			return nil, fmt.Errorf("failed to unmarshall %s", value)
		}
	}
	return result, nil
}
