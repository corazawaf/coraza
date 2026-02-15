// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"io"
	"strconv"
	"strings"

	"github.com/valyala/fastjson"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type jsonBodyProcessor struct{}

var _ plugintypes.BodyProcessor = &jsonBodyProcessor{}

func (js *jsonBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	// Read the entire body to store it and process it
	s := strings.Builder{}
	if _, err := io.Copy(&s, reader); err != nil {
		return err
	}
	ss := s.String()

	// Process as normal
	col := v.ArgsPost()
	data, err := readJSON(ss)
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
		txVar.Set("json_request_body", []string{ss})
	}

	return nil
}

func (js *jsonBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, _ plugintypes.BodyProcessorOptions) error {
	// Read the entire body to store it and process it
	s := strings.Builder{}
	if _, err := io.Copy(&s, reader); err != nil {
		return err
	}
	ss := s.String()

	// Process as normal
	col := v.ResponseArgs()
	data, err := readJSON(ss)
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
		txVar.Set("json_response_body", []string{ss})
	}

	return nil
}

func readJSON(s string) (map[string]string, error) {
	var p fastjson.Parser
	v, err := p.Parse(s)
	if err != nil {
		return nil, err
	}
	res := make(map[string]string)
	key := []byte("json")
	readItems(v, key, res)
	return res, nil
}

// Transform JSON to a map[string]string
// Example input: {"data": {"name": "John", "age": 30}, "items": [1,2,3]}
// Example output: map[string]string{"json.data.name": "John", "json.data.age": "30", "json.items.0": "1", "json.items.1": "2", "json.items.2": "3"}
// Example input: [{"data": {"name": "John", "age": 30}, "items": [1,2,3]}]
// Example output: map[string]string{"json.0.data.name": "John", "json.0.data.age": "30", "json.0.items.0": "1", "json.0.items.1": "2", "json.0.items.2": "3"}
func readItems(v *fastjson.Value, objKey []byte, res map[string]string) {
	switch v.Type() {
	case fastjson.TypeObject:
		o, _ := v.Object()
		o.Visit(func(k []byte, val *fastjson.Value) {
			// Avoid string concatenation to maintain a single buffer for key aggregation.
			prevLen := len(objKey)
			objKey = append(objKey, '.')
			objKey = append(objKey, k...)
			readValue(val, objKey, res)
			objKey = objKey[:prevLen]
		})
	case fastjson.TypeArray:
		arr, _ := v.Array()
		for i, val := range arr {
			prevLen := len(objKey)
			objKey = append(objKey, '.')
			objKey = strconv.AppendInt(objKey, int64(i), 10)
			readValue(val, objKey, res)
			objKey = objKey[:prevLen]
		}
		if len(arr) > 0 {
			res[string(objKey)] = strconv.Itoa(len(arr))
		}
	}
}

func readValue(v *fastjson.Value, objKey []byte, res map[string]string) {
	switch v.Type() {
	case fastjson.TypeObject, fastjson.TypeArray:
		readItems(v, objKey, res)
	case fastjson.TypeString:
		res[string(objKey)] = string(v.GetStringBytes())
	case fastjson.TypeNull:
		res[string(objKey)] = ""
	default:
		// TypeNumber, TypeTrue, TypeFalse — raw JSON representation
		res[string(objKey)] = string(v.MarshalTo(nil))
	}
}

func init() {
	RegisterBodyProcessor("json", func() plugintypes.BodyProcessor {
		return &jsonBodyProcessor{}
	})
}
