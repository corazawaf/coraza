// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"io"
	"strconv"

	"github.com/buger/jsonparser"

	"github.com/corazawaf/coraza/v3/rules"
)

type jsonBodyProcessor struct {
}

func (js *jsonBodyProcessor) ProcessRequest(reader io.Reader, v rules.TransactionVariables, _ Options) error {
	col := v.ArgsPost()
	data, err := readJSON(reader)
	if err != nil {
		return err
	}
	argsGetCol := v.ArgsGet()
	for key, value := range data {
		// TODO: This hack prevent GET variables from overriding POST variables
		for k := range argsGetCol.Data() {
			if k == key {
				argsGetCol.Remove(k)
			}
		}
		col.SetIndex(key, 0, value)
	}
	return nil
}

func (js *jsonBodyProcessor) ProcessResponse(reader io.Reader, v rules.TransactionVariables, _ Options) error {
	return nil
}

func readJSON(reader io.Reader) (map[string]string, error) {
	// dump reader to byte array
	var data []byte
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		data = append(data, buf[:n]...)
	}
	fields, err := jsonToMap(data)
	if err != nil {
		return nil, err
	}
	return fields, nil
}

// Transform JSON to a map[string]string
// Example input: {"data": {"name": "John", "age": 30}, "items": [1,2,3]}
// Example output: map[string]string{"json.data.name": "John", "json.data.age": "30", "json.items.0": "1", "json.items.1": "2", "json.items.2": "3"}
// Example input: [{"data": {"name": "John", "age": 30}, "items": [1,2,3]}]
// Example output: map[string]string{"json.0.data.name": "John", "json.0.data.age": "30", "json.0.items.0": "1", "json.0.items.1": "2", "json.0.items.2": "3"}
// TODO add some anti DOS protection
func jsonToMap(data []byte) (map[string]string, error) {
	res := make(map[string]string)
	err := readObject(data, "json", res)
	if errors.Is(err, jsonparser.MalformedObjectError) {
		err = readArray(data, "json", res)
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func readObject(data []byte, parentKey string, res map[string]string) error {
	return jsonparser.ObjectEach(data, func(key []byte, value []byte, dataType jsonparser.ValueType, offset int) error {
		objkey := parentKey + "." + string(key)
		switch dataType {
		case jsonparser.Object:
			return readObject(value, objkey, res)
		case jsonparser.Array:
			return readArray(value, objkey, res)
		default:
			res[objkey] = readValue(value, dataType)
		}
		return nil
	})
}

func readArray(data []byte, parentKey string, res map[string]string) error {
	idx := 0
	var err error
	_, err = jsonparser.ArrayEach(data, func(value []byte, dataType jsonparser.ValueType, _ int, _ error) {
		objkey := parentKey + "." + strconv.Itoa(idx)
		switch dataType {
		case jsonparser.Object:
			// Workaround https://github.com/buger/jsonparser/issues/255
			if localErr := readObject(value, objkey, res); localErr != nil {
				err = localErr
			}
		case jsonparser.Array:
			if localErr := readArray(value, objkey, res); localErr != nil {
				err = localErr
			}
		default:
			res[objkey] = readValue(value, dataType)
		}
		idx++
	})
	if err != nil {
		return err
	}
	res[parentKey] = strconv.Itoa(idx)
	return nil
}

func readValue(value []byte, dataType jsonparser.ValueType) string {
	switch dataType {
	case jsonparser.String:
		if s, err := jsonparser.ParseString(value); err == nil {
			return s
		} else {
			// Fallback to original string if any illegal escape sequences
			return string(value)
		}
	case jsonparser.Null:
		return ""
	}
	// String representation is same as JSON representation for all other types
	return string(value)
}

var _ BodyProcessor = &jsonBodyProcessor{}

func init() {
	Register("json", func() BodyProcessor {
		return &jsonBodyProcessor{}
	})
}
