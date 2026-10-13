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
	v := corazawaf.NewTransactionVariables()
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

// TestURLEncodeArgumentLimit is a regression test for GHSA-3ww9-vw83-9w5x:
// the urlencoded body processor used to populate ARGS_POST directly with no
// bound, ignoring SecArgumentsLimit entirely.
func TestURLEncodeArgumentLimit(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables()

	var body strings.Builder
	for i := 0; i < 10000; i++ {
		if i > 0 {
			body.WriteByte('&')
		}
		body.WriteString("a")
		body.WriteString(strconv.Itoa(i))
		body.WriteString("=1")
	}

	if err := bp.ProcessRequest(strings.NewReader(body.String()), v, plugintypes.BodyProcessorOptions{
		ArgumentLimit: 1000,
	}); err != nil {
		t.Fatal(err)
	}

	total := 0
	for i := 0; i < 10000; i++ {
		if got := v.ArgsPost().Get("a" + strconv.Itoa(i)); len(got) > 0 {
			total++
		}
	}
	if total != 1000 {
		t.Errorf("expected exactly 1000 ARGS_POST entries, got %d", total)
	}
	if v.ArgumentsLimitReached().Get() != "1" {
		t.Error("expected ARGUMENTS_LIMIT_REACHED to be set")
	}
}

// TestURLEncodeArgumentLimitRepeatedKey is a regression test confirming the
// limit bounds the total number of values, not just distinct keys: many
// values under one repeated key must still be capped.
func TestURLEncodeArgumentLimitRepeatedKey(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables()

	body := strings.TrimSuffix(strings.Repeat("a=1&", 10000), "&")

	if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{
		ArgumentLimit: 1000,
	}); err != nil {
		t.Fatal(err)
	}

	if got := len(v.ArgsPost().Get("a")); got != 1000 {
		t.Errorf("expected exactly 1000 values under repeated key 'a', got %d", got)
	}
	if v.ArgumentsLimitReached().Get() != "1" {
		t.Error("expected ARGUMENTS_LIMIT_REACHED to be set")
	}
}

func TestURLEncodeNoArgumentLimit(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		t.Fatal(err)
	}
	v := corazawaf.NewTransactionVariables()

	body := "a=1&b=2&c=3"
	if err := bp.ProcessRequest(strings.NewReader(body), v, plugintypes.BodyProcessorOptions{}); err != nil {
		t.Fatal(err)
	}
	if v.ArgumentsLimitReached().Get() == "1" {
		t.Error("expected ARGUMENTS_LIMIT_REACHED to be unset when ArgumentLimit is 0 (no limit)")
	}
	for _, k := range []string{"a", "b", "c"} {
		if len(v.ArgsPost().Get(k)) == 0 {
			t.Errorf("expected ARGS_POST to contain %q", k)
		}
	}
}

func BenchmarkURLEncodeArgumentLimit(b *testing.B) {
	var body strings.Builder
	for i := 0; i < 10000; i++ {
		if i > 0 {
			body.WriteByte('&')
		}
		body.WriteString("a")
		body.WriteString(strconv.Itoa(i))
		body.WriteString("=1")
	}
	bodyStr := body.String()

	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		v := corazawaf.NewTransactionVariables()
		if err := bp.ProcessRequest(strings.NewReader(bodyStr), v, plugintypes.BodyProcessorOptions{
			ArgumentLimit: 1000,
		}); err != nil {
			b.Fatal(err)
		}
	}
}
