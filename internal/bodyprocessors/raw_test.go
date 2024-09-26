// Copyright 2024 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/redwanghb/coraza/v3/experimental/plugins/plugintypes"
	"github.com/redwanghb/coraza/v3/internal/bodyprocessors"
	"github.com/redwanghb/coraza/v3/internal/corazawaf"
)

func TestRAW(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("raw")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables()

	body := `this is a body
without &any=meaning`
	if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{}); err != nil {
		t.Error(err)
	}
	if v.RequestBody().Get() != body {
		t.Errorf("Expected %s, got %s", body, v.RequestBody().Get())
	}
	if rbl, _ := strconv.Atoi(v.RequestBodyLength().Get()); rbl != len(body) {
		t.Errorf("Expected %d, got %s", len(body), v.RequestBodyLength().Get())
	}
}
