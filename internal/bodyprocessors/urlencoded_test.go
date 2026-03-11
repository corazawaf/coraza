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

func TestURLEncodeRawValues(t *testing.T) {
	bp, err := bodyprocessors.GetBodyProcessor("urlencoded")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		body         string
		wantCooked   map[string]string // decoded value in ArgsPost
		wantRaw      map[string]string // raw value in ArgsPostRaw
	}{
		{
			name:       "percent-encoded value",
			body:       "key=%3Cscript%3E",
			wantCooked: map[string]string{"key": "<script>"},
			wantRaw:    map[string]string{"key": "%3Cscript%3E"},
		},
		{
			name:       "double-encoded value",
			body:       "password=Secret%2500",
			wantCooked: map[string]string{"password": "Secret%00"},
			wantRaw:    map[string]string{"password": "Secret%2500"},
		},
		{
			name:       "plus sign preserved in raw",
			body:       "q=hello+world",
			wantCooked: map[string]string{"q": "hello world"},
			wantRaw:    map[string]string{"q": "hello+world"},
		},
		{
			name:       "plain value identical in both",
			body:       "plain=hello",
			wantCooked: map[string]string{"plain": "hello"},
			wantRaw:    map[string]string{"plain": "hello"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := corazawaf.NewTransactionVariables()
			if err := bp.ProcessRequest(strings.NewReader(tc.body), v, plugintypes.BodyProcessorOptions{}); err != nil {
				t.Fatal(err)
			}
			for k, want := range tc.wantCooked {
				got := v.ArgsPost().Get(k)
				if len(got) == 0 || got[0] != want {
					t.Errorf("ArgsPost[%q]: got %v, want %q", k, got, want)
				}
			}
			for k, want := range tc.wantRaw {
				got := v.ArgsPostRaw().Get(k)
				if len(got) == 0 || got[0] != want {
					t.Errorf("ArgsPostRaw[%q]: got %v, want %q", k, got, want)
				}
			}
		})
	}
}

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
