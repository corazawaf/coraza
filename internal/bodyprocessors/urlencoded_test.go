// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func TestURLEncode(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables(nil)
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
	if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{}); err != nil {
		t.Error(err)
	}
	if v.RequestBody().Get() != body {
		t.Errorf("Expected %s, got %s", body, v.RequestBody().Get())
	}
	if rbl, _ := strconv.Atoi(v.RequestBodyLength().Get()); rbl != len(body) {
		t.Errorf("Expected %d, got %s", len(body), v.RequestBodyLength().Get())
	}
	for k, val := range m {
		if v.ArgsPost().Get(k)[0] != val {
			t.Errorf("Expected %s, got %s", val, v.ArgsPost().Get(k)[0])
		}
	}
}
