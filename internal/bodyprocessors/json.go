// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

const ResponseBodyRecursionLimit = -1

type jsonBodyProcessor struct{}

var _ plugintypes.BodyProcessor = &jsonBodyProcessor{}

func (js *jsonBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, bpo plugintypes.BodyProcessorOptions) error {
	col := v.ArgsPost()
	data, err := readJSON(reader, bpo.RequestBodyRecursionLimit)
	if err != nil {
		return err
	}
	for key, value := range data {
		col.SetIndex(key, 0, value)
	}
	return nil
}

func (js *jsonBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	col := v.ResponseArgs()
	data, err := readJSON(reader, ResponseBodyRecursionLimit)
	if err != nil {
		return err
	}
	for key, value := range data {
		col.SetIndex(key, 0, value)
	}
	return nil
}

func readJSON(reader io.Reader, maxRecursion int) (map[string]string, error) {
	s := strings.Builder{}
	_, err := io.Copy(&s, reader)
	if err != nil {
		return nil, err
	}

	res := make(map[string]string)
	key := []byte("json")


	if !gjson.Valid(s.String()) {
		return res, errors.New("invalid JSON")
	}
	json := gjson.Parse(s.String())
	err = readItems(json, key, maxRecursion, res)
	return res, err
}

// Transform JSON to a map[string]string
// This function is recursive and will call itself for nested objects.
// The limit in recursion is defined by maxItems.
// Example input: {"data": {"name": "John", "age": 30}, "items": [1,2,3]}
// Example output: map[string]string{"json.data.name": "John", "json.data.age": "30", "json.items.0": "1", "json.items.1": "2", "json.items.2": "3"}
// Example input: [{"data": {"name": "John", "age": 30}, "items": [1,2,3]}]
// Example output: map[string]string{"json.0.data.name": "John", "json.0.data.age": "30", "json.0.items.0": "1", "json.0.items.1": "2", "json.0.items.2": "3"}
func readItems(json gjson.Result, objKey []byte, maxRecursion int, res map[string]string) error {
	arrayLen := 0
	var iterationError error
	if maxRecursion == 0 {
		// we reached the limit of nesting we want to handle
		return errors.New("max recursion reached while reading json object")
	}
	json.ForEach(func(key, value gjson.Result) bool {
		// Avoid string concatenation to maintain a single buffer for key aggregation.
		prevParentLength := len(objKey)
		objKey = append(objKey, '.')
		if key.Type == gjson.String {
			objKey = append(objKey, key.Str...)
		} else {
			objKey = strconv.AppendInt(objKey, int64(key.Num), 10)
			arrayLen++
		}

		var val string
		switch value.Type {
		case gjson.JSON:
			// call recursively with one less item to avoid doing infinite recursion
			iterationError = readItems(value, objKey, maxRecursion-1, res)
			if iterationError != nil {
				return false
			}
			objKey = objKey[:prevParentLength]
			return true
		case gjson.String:
			val = value.Str
		case gjson.Null:
			val = ""
		default:
			// For all other types, raw JSON is what we need
			val = value.Raw
		}

		res[string(objKey)] = val
		objKey = objKey[:prevParentLength]

		return true
	})
	if arrayLen > 0 {
		res[string(objKey)] = strconv.Itoa(arrayLen)
	}
	return iterationError
}

func init() {
	RegisterBodyProcessor("json", func() plugintypes.BodyProcessor {
		return &jsonBodyProcessor{}
	})
}
