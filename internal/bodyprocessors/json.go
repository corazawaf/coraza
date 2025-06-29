// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"io"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type jsonBodyProcessor struct{}

var _ plugintypes.BodyProcessor = &jsonBodyProcessor{}

func (js *jsonBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	// Read the entire body to store it and process it
	s := strings.Builder{}
	tr := io.TeeReader(reader, &s)

	// Process as normal
	col := v.ArgsPost()
	data, err := readJSON(tr)
	if err != nil {
		return err
	}
	for key, value := range data {
		col.SetIndex(key, 0, value)
	}

	// Store the raw JSON in the TX variable for validateSchema
	// This is needed because RequestBody is a Single interface without a Set method
	if txVar := v.TX(); txVar != nil {
		// Store the content type and raw body
		txVar.Set("json_request_body", []string{s.String()})
	}

	return nil
}

func (js *jsonBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	// Read the entire body to store it and process it
	s := strings.Builder{}
	tr := io.TeeReader(reader, &s)

	// Process as normal
	col := v.ResponseArgs()
	data, err := readJSON(tr)
	if err != nil {
		return err
	}
	for key, value := range data {
		col.SetIndex(key, 0, value)
	}

	// Store the raw JSON in the TX variable for validateSchema
	// This is needed because ResponseBody is a Single interface without a Set method
	if txVar := v.TX(); txVar != nil && v.ResponseBody() != nil {
		// Store the content type and raw body
		txVar.Set("json_response_body", []string{s.String()})
	}

	return nil
}

func readJSON(reader io.Reader) (map[string]string, error) {
	s := strings.Builder{}
	_, err := io.Copy(&s, reader)
	if err != nil {
		return nil, err
	}

	json := gjson.Parse(s.String())
	res := make(map[string]string)
	key := []byte("json")
	readItems(json, key, res)
	return res, nil
}

// Transform JSON to a map[string]string
// Example input: {"data": {"name": "John", "age": 30}, "items": [1,2,3]}
// Example output: map[string]string{"json.data.name": "John", "json.data.age": "30", "json.items.0": "1", "json.items.1": "2", "json.items.2": "3"}
// Example input: [{"data": {"name": "John", "age": 30}, "items": [1,2,3]}]
// Example output: map[string]string{"json.0.data.name": "John", "json.0.data.age": "30", "json.0.items.0": "1", "json.0.items.1": "2", "json.0.items.2": "3"}
// TODO add some anti DOS protection
func readItems(json gjson.Result, objKey []byte, res map[string]string) {
	arrayLen := 0
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
			readItems(value, objKey, res)
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
}

func init() {
	RegisterBodyProcessor("json", func() plugintypes.BodyProcessor {
		return &jsonBodyProcessor{}
	})
}
