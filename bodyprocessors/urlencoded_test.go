// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

func TestURLEncode(t *testing.T) {
	bp := &urlencodedBodyProcessor{}
	argCol := collection.NewMap(variables.ArgsPost)
	bodyCol := collection.NewSimple(variables.RequestBody)
	bodyLenCol := collection.NewSimple(variables.RequestBodyLength)
	cols := [types.VariablesCount]collection.Collection{
		variables.ArgsPost:          argCol,
		variables.RequestBody:       bodyCol,
		variables.RequestBodyLength: bodyLenCol,
	}
	m := map[string]string{
		"a": "1",
		"b": "2",
		"c": "3",
	}
	// m to urlencoded string
	body := ""
	for k, v := range m {
		body += k + "=" + v + "&"
	}
	body = strings.TrimSuffix(body, "&")
	if err := bp.ProcessRequest(strings.NewReader(body), cols, Options{}); err != nil {
		t.Error(err)
	}
	if bodyCol.String() != body {
		t.Errorf("Expected %s, got %s", body, bodyCol.String())
	}
	if bodyLenCol.Int() != len(body) {
		t.Errorf("Expected %d, got %s", len(body), bodyLenCol.String())
	}
	for k, v := range m {
		if argCol.Get(k)[0] != v {
			t.Errorf("Expected %s, got %s", v, argCol.Get(k)[0])
		}
	}
}
