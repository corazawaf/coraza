// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package bodyprocessors_test

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/bodyprocessors"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

func wideJSONArray(n int) string {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("1")
	}
	sb.WriteString("]")
	return sb.String()
}

// TestJSONProcessRequestArgumentLimit is a regression test for
// GHSA-3ww9-vw83-9w5x: the JSON body processor used to add every flattened
// field to ARGS_POST with no bound, so a small body decoding to a wide flat
// array (e.g. [1,1,1,...]) expanded into millions of ARGS_POST entries
// regardless of SecArgumentsLimit.
func TestJSONProcessRequestArgumentLimit(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables()

	if err := bp.ProcessRequest(strings.NewReader(wideJSONArray(10000)), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 100,
		ArgumentLimit:             1000,
	}); err != nil {
		t.Fatal(err)
	}

	if got := len(v.ArgsPost().FindAll()); got > 1001 {
		t.Errorf("expected at most ~1000 ARGS_POST entries, got %d", got)
	}
	if v.ArgumentsLimitReached().Get() != "1" {
		t.Error("expected ARGUMENTS_LIMIT_REACHED to be set")
	}
}

func TestJSONProcessResponseArgumentLimit(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables()

	if err := bp.ProcessResponse(strings.NewReader(wideJSONArray(10000)), v, plugintypes.BodyProcessorOptions{
		ArgumentLimit: 1000,
	}); err != nil {
		t.Fatal(err)
	}

	if got := len(v.ResponseArgs().FindAll()); got > 1001 {
		t.Errorf("expected at most ~1000 RESPONSE_ARGS entries, got %d", got)
	}
	if v.ArgumentsLimitReached().Get() != "1" {
		t.Error("expected ARGUMENTS_LIMIT_REACHED to be set")
	}
}

func TestJSONProcessRequestNoArgumentLimit(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables()

	if err := bp.ProcessRequest(strings.NewReader(`{"a":1,"b":2,"c":3}`), v, plugintypes.BodyProcessorOptions{
		RequestBodyRecursionLimit: 100,
	}); err != nil {
		t.Fatal(err)
	}

	if v.ArgumentsLimitReached().Get() == "1" {
		t.Error("expected ARGUMENTS_LIMIT_REACHED to be unset when ArgumentLimit is 0 (no limit)")
	}
	for _, k := range []string{"json.a", "json.b", "json.c"} {
		if len(v.ArgsPost().Get(k)) == 0 {
			t.Errorf("expected ARGS_POST to contain %q", k)
		}
	}
}

func BenchmarkJSONProcessRequestArgumentLimit(b *testing.B) {
	body := wideJSONArray(100000)
	bp, err := bodyprocessors.GetBodyProcessor("json")
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		v := corazawaf.NewTransactionVariables()
		if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
			RequestBodyRecursionLimit: 100,
			ArgumentLimit:             1000,
		}); err != nil {
			b.Fatal(err)
		}
	}
}
